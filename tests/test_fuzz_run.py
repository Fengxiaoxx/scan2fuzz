"""Verify the merged AFL++ runner and its selector-only seed protocol."""

from pathlib import Path
from contextlib import redirect_stdout
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest
from unittest.mock import patch

from src.core.config import build_compile_flags, build_include_paths
from src.fuzz_run.runner import (
    RunOptions,
    _Driver,
    _DEFAULT_AFL_CC,
    _DEFAULT_AFL_FUZZ,
    _load_drivers,
    _write_initial_corpus,
    _repetition_status,
    _write_merged_sources,
    run_fuzz,
)
from src.fuzz_run.selector_seeds import driver_ids_from_entry, write_selector_seeds
from src.cli import fuzz_run as fuzz_cli
from src.cli import fuzz_build as build_cli
from src.experiment.store import RunArtifactStore


class FuzzRunTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def _drivers(self, count=3):
        drivers = []
        for index in range(count):
            source = self.root / f"driver_{index}.cc"
            source.write_text(
                '#include <stdint.h>\n#include <stddef.h>\n'
                f'extern "C" int LLVMFuzzerTestOneInput(const uint8_t*, size_t size) '
                f'{{ return size == 0 ? {index + 1} : {index + 11}; }}\n',
                encoding="utf-8",
            )
            drivers.append(_Driver(f"driver_{index}", source))
        return tuple(drivers)

    def test_empty_corpus_has_one_unique_selector_per_driver_without_entering_drivers(self):
        drivers = self._drivers()
        corpus = self.root / "corpus"
        self.assertEqual(_write_initial_corpus(drivers, corpus), 3)
        seeds = sorted(corpus.iterdir())
        self.assertEqual([seed.read_bytes() for seed in seeds], [b"\x00", b"\x01", b"\x02"])

        compiler = shutil.which("c++")
        if compiler is None:
            self.skipTest("C++ compiler unavailable")
        entry, _ = _write_merged_sources(drivers, self.root / "merged")
        self.assertEqual(driver_ids_from_entry(entry, "trace2fuzz"), tuple(d.driver_id for d in drivers))
        main = self.root / "main.cc"
        main.write_text(
            '#include <stdint.h>\n#include <stdio.h>\n'
            'extern "C" int LLVMFuzzerTestOneInput(const uint8_t*, size_t);\n'
            'int main() { uint8_t input[2]; size_t size = fread(input, 1, 2, stdin); '
            'printf("%d", LLVMFuzzerTestOneInput(input, size)); return 0; }\n',
            encoding="utf-8",
        )
        binary = self.root / "merged_test"
        subprocess.run(
            [compiler, str(entry), *sorted(map(str, (entry.parent / "drivers").glob("*.cc"))),
             str(main), "-o", str(binary)],
            check=True,
            capture_output=True,
        )
        for index, seed in enumerate(seeds):
            result = subprocess.run([str(binary)], input=seed.read_bytes(), capture_output=True, check=True)
            self.assertEqual(result.stdout, b"0")
            result = subprocess.run(
                [str(binary)], input=seed.read_bytes() + b"\x41", capture_output=True, check=True
            )
            self.assertEqual(result.stdout, str(index + 11).encode())

    def test_one_byte_selector_rejects_more_than_256_drivers(self):
        drivers = self._drivers(count=257)
        with self.assertRaisesRegex(ValueError, "one-byte selector"):
            _write_initial_corpus(drivers, self.root / "corpus")

    def test_promptfuzz_selector_is_two_bytes_big_endian(self):
        corpus = self.root / "promptfuzz"
        names = tuple(f"driver_{index}" for index in range(260))
        self.assertEqual(write_selector_seeds(corpus, names, selector_bytes=2, byteorder="big"), 260)
        self.assertEqual((corpus / "selector_00003_driver_3").read_bytes(), b"\x00\x03")
        self.assertEqual((corpus / "selector_00259_driver_259").read_bytes(), b"\x01\x03")
        self.assertEqual(len(list(corpus.iterdir())), 260)
        with self.assertRaisesRegex(ValueError, "not empty"):
            write_selector_seeds(corpus, names, selector_bytes=2, byteorder="big")

    def test_promptfuzz_selector_matches_actual_provider(self):
        header = Path(__file__).resolve().parents[1] / "PromptFuzz/src/extern/FuzzedDataProvider.h"
        compiler = shutil.which("c++")
        if not header.is_file() or compiler is None:
            self.skipTest("PromptFuzz provider or C++ compiler unavailable")
        source = self.root / "selector.cc"
        source.write_text(
            '#include <stdint.h>\n#include <stdio.h>\n#include "FuzzedDataProvider.h"\n'
            'int main() { uint8_t data[2]; if (fread(data,1,2,stdin) != 2) return 2; '
            'FuzzedDataProvider fdp(data,2); '
            'FDPConsumeIntegral(uint16_t, switch_id, fdp); '
            'printf("%u", unsigned(switch_id)); }\n',
            encoding="utf-8",
        )
        binary = self.root / "selector"
        subprocess.run(
            [compiler, "-std=c++17", "-I", str(header.parent), str(source), "-o", str(binary)],
            check=True, capture_output=True,
        )
        for index in (0, 3, 259):
            seed = index.to_bytes(2, "big")
            result = subprocess.run([str(binary)], input=seed, capture_output=True, check=True)
            self.assertEqual(result.stdout, str(index).encode())

    def test_promptfuzz_entry_drives_seed_count_and_order(self):
        entry = self.root / "entry.cc"
        entry.write_text(
            "FDPConsumeIntegral(uint16_t, switch_id, fdp);\n"
            "switch (switch_id) {\n"
            "case 0: return LLVMFuzzerTestOneInput_id_000042(input, i_size);\n"
            "case 1: return LLVMFuzzerTestOneInput_id_000071(input, i_size);\n}"
        )
        self.assertEqual(driver_ids_from_entry(entry, "promptfuzz"), ("id_000042", "id_000071"))

    def test_campaign_requires_live_stats_and_accepted_exit(self):
        self.assertEqual(_repetition_status({"returncode": 124, "stats": {"run_time": "42"}}), "completed")
        self.assertEqual(_repetition_status({"returncode": 0, "stats": {}}), "failed")
        self.assertEqual(_repetition_status({"returncode": 1, "stats": {"run_time": "42"}}), "partial")
        self.assertEqual(_repetition_status({"error": "launch failed", "stats": {}}), "failed")

    def test_driver_inventory_requires_only_sources(self):
        inventory = [type("Entry", (), {"driver_id": "one", "source_path": self.root / "one.cc"})()]
        options = RunOptions(self.root, "sample", "run-001")
        with patch("src.fuzz_run.runner.load_fuzzable_drivers", return_value=(self.root, inventory)):
            drivers = _load_drivers(options)
        self.assertEqual(len(drivers), 1)
        self.assertEqual(drivers[0].source, self.root / "one.cc")

    def test_final_fuzz_links_separate_aflpp_library(self):
        config = {"compile_config": {
            "sanitize_library": "./test_lib/lcms/build_sanitize/src/.libs/liblcms2.a",
            "additional_libs": ["-lm", "-lpthread"],
        }}
        with patch("src.core.config.load_library_config", return_value=config):
            with patch("src.core.config.build_include_paths", return_value=["-Ipublic"]):
                final_flags = build_compile_flags("lcms", library_variant="aflpp")
                reach_flags = build_compile_flags("lcms")
        self.assertIn("test_lib/lcms/build_aflpp/src/.libs/liblcms2.a", final_flags)
        self.assertIn("test_lib/lcms/build_sanitize/src/.libs/liblcms2.a", reach_flags)
        self.assertTrue(final_flags.endswith("-lm -lpthread"))

    def test_generated_public_headers_are_found_in_variant_include_directory(self):
        generated = self.root / "test_lib" / "c-ares" / "build_aflpp" / "include"
        generated.mkdir(parents=True)
        (generated / "ares_build.h").write_text("#define ARES_BUILD 1\n")
        with patch("src.core.config.PROJECT_ROOT", self.root), patch(
            "src.core.config.load_library_config", return_value={"public_api": {}}
        ), patch.dict(os.environ, {"RUN_DIR": ""}):
            flags = build_include_paths("c-ares", "aflpp")
        self.assertIn(f"-I{generated}", flags)

        frozen = self.root / "workspace" / "c-ares" / "runs" / "run-001" / "stages" / "scan" / "public-install" / "include"
        frozen.mkdir(parents=True)
        (frozen / "ares_build.h").write_text("#define ARES_BUILD 1\n")
        with patch("src.core.config.PROJECT_ROOT", self.root), patch(
            "src.core.config.load_library_config", return_value={"public_api": {}}
        ), patch.dict(os.environ, {"RUN_DIR": ""}):
            flags = build_include_paths("c-ares", "aflpp", run_dir=frozen.parents[3])
        self.assertEqual(flags, [f"-I{frozen}"])

    def test_final_fuzz_defaults_to_pinned_aflpp_not_system_path(self):
        self.assertTrue(Path(_DEFAULT_AFL_CC).is_absolute())
        self.assertTrue(Path(_DEFAULT_AFL_FUZZ).is_absolute())
        self.assertEqual(Path(_DEFAULT_AFL_CC).parent, Path(_DEFAULT_AFL_FUZZ).parent)
        self.assertEqual(Path(_DEFAULT_AFL_CC).parent.name, "4.33c")

    def test_final_runner_builds_asan_ubsan_with_selector_only_seeds(self):
        compiler = self.root / "afl-clang-fast++"
        compiler.write_text(textwrap.dedent("""\
            #!/usr/bin/env python3
            import json, os, pathlib, sys
            if '-h' in sys.argv:
                print('afl-clang-fast++ 4.33c')
                sys.exit(0)
            args = sys.argv[1:]
            output = pathlib.Path(args[args.index('-o') + 1])
            output.write_text('#!/bin/sh\\nexit 0\\n')
            output.chmod(0o755)
            (output.parent / 'build-record.json').write_text(json.dumps({
                'args': args,
                'asan': os.environ.get('AFL_USE_ASAN'),
                'ubsan': os.environ.get('AFL_USE_UBSAN'),
                'msan': os.environ.get('AFL_USE_MSAN'),
            }))
        """), encoding="utf-8")
        compiler.chmod(0o755)
        fuzzer = self.root / "afl-fuzz"
        fuzzer.write_text(textwrap.dedent("""\
            #!/usr/bin/env python3
            import json, os, pathlib, sys
            if '-V' in sys.argv:
                print('afl-fuzz++ 4.33c')
                sys.exit(0)
            args = sys.argv[1:]
            corpus = pathlib.Path(args[args.index('-i') + 1])
            output = pathlib.Path(args[args.index('-o') + 1])
            (output / 'default' / 'crashes').mkdir(parents=True)
            (output / 'default' / 'fuzzer_stats').write_text('run_time : 1\\n')
            (output / 'runtime-record.json').write_text(json.dumps({
                'seeds': [p.read_bytes().hex() for p in sorted(corpus.iterdir())],
                'timeout': args[args.index('-t') + 1],
                'asan': os.environ.get('ASAN_OPTIONS'),
                'ubsan': os.environ.get('UBSAN_OPTIONS'),
                'msan': os.environ.get('MSAN_OPTIONS'),
                'exitcode': os.environ.get('AFL_CRASH_EXITCODE'),
            }))
        """), encoding="utf-8")
        fuzzer.chmod(0o755)
        (self.root / "libAFLDriver.a").write_bytes(b"fake archive")

        drivers = self._drivers(2)
        archive = self.root / "test_lib" / "lcms" / "build_aflpp" / "liblcms.a"
        archive.parent.mkdir(parents=True)
        archive.write_bytes(b"fake archive")
        options = RunOptions(
            self.root, "lcms", "run-asan", repetitions=1,
            seconds_per_run=2, concurrency=1, timeout_ms=5000,
        )
        with patch.dict(os.environ, {
            "TRACE2FUZZ_AFL_CC": str(compiler),
            "TRACE2FUZZ_AFL_FUZZ": str(fuzzer),
        }), patch("src.fuzz_run.runner._load_drivers", return_value=drivers), patch(
            "src.fuzz_run.runner.build_compile_flags", return_value=str(archive.relative_to(self.root))
        ):
            summary = run_fuzz(options)
        self.assertEqual(summary["status"], "completed")
        self.assertEqual(summary["seed_mode"], "selector_only")
        self.assertEqual(summary["seed_count"], 2)
        directory = Path(summary["output_dir"])
        self.assertEqual(json.loads((directory / "result.json").read_text())["profile"], "asan_ubsan")
        build = json.loads((directory / "build-record.json").read_text())
        runtime = json.loads((directory / "rep_00" / "out" / "runtime-record.json").read_text())
        self.assertIn(str(archive.relative_to(self.root)), build["args"])
        self.assertIn("-std=c++17", build["args"])
        self.assertEqual(runtime["seeds"], ["00", "01"])
        self.assertEqual(runtime["timeout"], "5000")
        self.assertIn("-fsanitize=address,undefined", build["args"])
        self.assertEqual(build["asan"], "1")
        self.assertEqual(build["ubsan"], "1")
        self.assertIsNone(build["msan"])
        self.assertIsNotNone(runtime["asan"])
        self.assertIsNotNone(runtime["ubsan"])
        self.assertIsNone(runtime["msan"])

    def test_cli_exposes_only_the_merged_campaign_settings(self):
        argv = [
            "fuzz_run", "lcms", "--run-id", "run-001",
            "--driver", "TARGET_0001", "--repetitions", "2",
            "--seconds-per-run", "3", "--concurrency", "1", "--timeout-ms", "2500",
        ]
        with patch.object(sys, "argv", argv), patch.object(
            fuzz_cli, "run_fuzz", return_value={"status": "completed", "output_dir": "/tmp/fuzz"}
        ) as run, redirect_stdout(io.StringIO()):
            self.assertEqual(fuzz_cli.main(), 0)
        options = run.call_args.args[0]
        self.assertEqual(options.drivers, ("TARGET_0001",))
        self.assertEqual((options.repetitions, options.seconds_per_run, options.concurrency, options.timeout_ms), (2, 3, 1, 2500))

    def test_build_cli_writes_one_asan_ubsan_binary_without_starting_fuzz(self):
        store = RunArtifactStore.create(self.root, "sample", "run-001")
        drivers = self._drivers(2)

        def fake_build(_options, work, _entry):
            binary = work / "merged_driver"
            binary.write_bytes(b"compiled")
            return binary

        argv = ["fuzz_build", "sample", "--run-id", store.run_id]
        fake_file = self.root / "src" / "cli" / "fuzz_build.py"
        with patch.object(sys, "argv", argv), patch.object(
            build_cli, "__file__", str(fake_file)
        ), patch.object(
            build_cli, "_prepare_library"
        ) as prepare, patch.object(
            build_cli, "_load_drivers", return_value=drivers
        ), patch.object(
            build_cli, "_build_merged", side_effect=fake_build
        ) as build, redirect_stdout(io.StringIO()):
            self.assertEqual(build_cli.main(), 0)

        self.assertEqual(prepare.call_count, 1)
        self.assertEqual(build.call_count, 1)
        manifests = list((self.root / "workspace" / "sample" / "fuzz_builds").rglob("build.json"))
        self.assertEqual(len(manifests), 1)
        self.assertEqual({json.loads(p.read_text())["profile"] for p in manifests},
                         {"asan_ubsan"})
        self.assertFalse(list((self.root / "workspace" / "sample").rglob("rep_*")))


if __name__ == "__main__":
    unittest.main()
