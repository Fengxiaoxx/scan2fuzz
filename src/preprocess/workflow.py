"""
Preprocessing workflow - orchestrates information extraction
"""

import hashlib
import json
import os
import shutil
import subprocess
import sys
from collections import Counter
from pathlib import Path

from loguru import logger

from src.core import get_project_root, load_library_config
from src.core.log_config import add_file_log_sink
from src.experiment import RunArtifactStore
from src.preprocess.api_declarations import build_public_api_declarations
from src.preprocess.docs.doc_generator import generate_all_lsp
from src.preprocess.driver_corpus import build_driver_corpus
from src.preprocess.extractors.port_extractor import PortExtractor
from src.preprocess.fact_base import build_fact_base
from src.preprocess.public_api_extractor import extract_public_api
from src.preprocess.reachability.candidate_plan import CandidatePlanBuilder
from src.preprocess.vector_index_builder import build_vector_index


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _same_compilation_database(current: Path, frozen: Path) -> bool:
    """Compare compilation commands while ignoring their nondeterministic order."""
    if not current.is_file() or not frozen.is_file():
        return False
    try:
        current_commands = json.loads(current.read_text(encoding="utf-8"))
        frozen_commands = json.loads(frozen.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return False
    if not isinstance(current_commands, list) or not isinstance(frozen_commands, list):
        return False

    def command_counts(commands: list) -> Counter:
        return Counter(
            json.dumps(command, sort_keys=True, separators=(",", ":"))
            for command in commands
        )

    return command_counts(current_commands) == command_counts(frozen_commands)


class PreprocessWorkflow:
    """Preprocessing workflow for library analysis"""

    def __init__(self, library_name: str, *, concurrency: int):
        self.library_name = library_name
        self.concurrency = concurrency
        self.info_lib_dir = f"info_lib/{library_name}"
        # Grouped subdirs (post-reorg 2026-05-27):
        # raw/      - structural CSVs and call graphs
        # api/      - per-API knowledge (docs, FAISS, interface cache)
        # targets/  - target analysis artefacts
        # build/    - bitcode + build log/hooks
        # external/ - third-party tool outputs (CodeQL DB, scanner reports)
        # txt/      - flat-list inputs (api_list.txt, targets.txt) — kept un-nested
        self.csv_dir = f"{self.info_lib_dir}/raw/csv"
        self.callgraph_dir = f"{self.info_lib_dir}/raw/callgraph"
        self.txt_dir = f"{self.info_lib_dir}/txt"
        self.config_file = f"{self.info_lib_dir}/config.yaml"
        self.api_list_file = f"{self.txt_dir}/api_list.txt"
        self.codeql_db = f"{self.info_lib_dir}/external/database"
        self.docs_dir = f"{self.info_lib_dir}/api/docs"
        self.targets_txt = f"{self.txt_dir}/targets.txt"
        self.library_root = f"test_lib/{library_name}"
        self.config = None
        self.api_doc_stats = None
        self.compile_commands_path = None

    # ------------------------------------------------------------------
    # Public entrypoint
    # ------------------------------------------------------------------

    def run(self) -> bool:
        """Execute preprocessing workflow."""
        run_store = RunArtifactStore.from_environment(
            get_project_root(), self.library_name
        )
        self.config_file = str(run_store.safe_path("config/config.yaml"))
        self.build_script = str(run_store.safe_path("config/build.sh"))
        self.targets_txt = str(run_store.safe_path("stages/scan/targets.txt"))
        self.compile_commands_path = str(
            run_store.safe_path("stages/scan/compile_commands.json")
        )
        log_path = run_store.logs_dir("preprocess") / "workflow.log"
        log_path.parent.mkdir(parents=True, exist_ok=True)
        sink_id = add_file_log_sink(str(log_path))
        try:
            logger.info(f"Preprocessing {self.library_name}...")

            if not self._load_config():
                return False
            self._reset_working_outputs()
            self._ensure_directories()
            if not self._setup_clangd_workspace():
                return False

            if not self._build_library_variants():
                return False

            if not self._extract_public_api(run_store):
                return False

            if not self._build_candidate_plan(run_store):
                return False
            if not self._extract_api_ports():
                return False
            if not self._build_api_declarations():
                return False
            if not self._build_driver_corpus():
                return False
            if not self._generate_api_docs(run_store):
                return False
            if not self._build_fact_base(run_store):
                return False
            if not self._build_vector_index(run_store):
                return False
            self._snapshot_run_artifacts(run_store)

            logger.success("Preprocessing completed!")
            return True
        finally:
            logger.remove(sink_id)

    def _snapshot_run_artifacts(self, store: RunArtifactStore) -> None:
        from src.llm import collect_agent_usage_metrics

        outputs = {
            self.api_list_file: "stages/preprocess/api_list.txt",
            f"{self.csv_dir}/function_locations.csv": (
                "stages/preprocess/structural/function_locations.csv"
            ),
            f"{self.csv_dir}/api_declarations.csv": (
                "stages/preprocess/structural/api_declarations.csv"
            ),
            f"{self.info_lib_dir}/api/public_api.json": (
                "stages/preprocess/structural/public_api.json"
            ),
            f"{self.txt_dir}/api_symbols.txt": (
                "stages/preprocess/api_symbols.txt"
            ),
            f"{self.callgraph_dir}/call_graph.high.csv": (
                "stages/preprocess/structural/call_graph.high.csv"
            ),
            f"{self.callgraph_dir}/call_graph.all.csv": (
                "stages/preprocess/structural/call_graph.all.csv"
            ),
            f"{self.callgraph_dir}/mapping.jsonl": (
                "stages/preprocess/structural/graph-mapping.jsonl"
            ),
            f"{self.callgraph_dir}/elf-alias-groups.json": (
                "stages/preprocess/structural/elf-alias-groups.json"
            ),
            f"{self.callgraph_dir}/summary.json": (
                "stages/preprocess/structural/graph-summary.json"
            ),
            f"{self.info_lib_dir}/raw/classify/api_ports.json": (
                "stages/preprocess/structural/api_ports.json"
            ),
            f"{self.info_lib_dir}/api/fact_base.json": (
                "stages/preprocess/fact_base.json"
            ),
            f"{self.info_lib_dir}/drivers.json": (
                "stages/preprocess/drivers.json"
            ),
            f"{self.info_lib_dir}/targets/candidate_plan.json": (
                "stages/preprocess/candidate_plan.json"
            ),
        }
        copied_outputs = list(outputs.values())
        for source, destination in outputs.items():
            store.copy_file_or_validate(source, destination)

        doc_index = store.read_json("stages/preprocess/api-doc-index.json")
        if not isinstance(doc_index, dict) or not doc_index:
            raise ValueError("preprocess produced no API document index")
        for api_id, relative_path in doc_index.items():
            document = store.read_json(relative_path)
            if not isinstance(document, dict) or document.get("api_id") != api_id:
                raise ValueError(f"invalid API document artifact: {relative_path}")

        faiss_outputs = []
        for name in ("index.faiss", "index.pkl"):
            destination = f"stages/preprocess/faiss-index/{name}"
            store.copy_file_or_validate(
                f"{self.info_lib_dir}/api/faiss_index/{name}",
                destination,
            )
            faiss_outputs.append(destination)
        store.write_json(
            "stages/preprocess/result.json",
            {
                "status": "completed",
                "outputs": [
                    *copied_outputs,
                    "stages/preprocess/api-doc-index.json",
                    *faiss_outputs,
                ],
                "api_document_count": len(doc_index),
                "api_document_generation": self.api_doc_stats,
                "agent_usage": collect_agent_usage_metrics(store)[
                    "shared_preprocess"
                ],
            },
        )

    # ------------------------------------------------------------------
    # Setup
    # ------------------------------------------------------------------

    def _load_config(self) -> bool:
        self.config = load_library_config(self.library_name)
        if not self.config:
            logger.error(f"Config file not found or failed to load: {self.config_file}")
            return False
        logger.debug(f"Loaded config from {self.config_file}")
        return True

    def _ensure_directories(self) -> None:
        os.makedirs(self.csv_dir, exist_ok=True)
        os.makedirs(self.callgraph_dir, exist_ok=True)
        os.makedirs(self.txt_dir, exist_ok=True)

    def _reset_working_outputs(self) -> None:
        """Remove global preprocess products before rebuilding this run."""
        directories = (
            self.csv_dir,
            self.callgraph_dir,
            f"{self.info_lib_dir}/raw/classify",
            f"{self.info_lib_dir}/api",
            f"{self.info_lib_dir}/targets",
        )
        for directory in directories:
            if os.path.exists(directory):
                shutil.rmtree(directory)

        files = (
            self.api_list_file,
            f"{self.txt_dir}/api_symbols.txt",
            f"{self.info_lib_dir}/drivers.json",
            f"{self.callgraph_dir}/call_graph.high.csv",
            f"{self.callgraph_dir}/call_graph.all.csv",
            f"{self.callgraph_dir}/mapping.jsonl",
            f"{self.callgraph_dir}/elf-alias-groups.json",
            f"{self.callgraph_dir}/summary.json",
        )
        for file_path in files:
            if os.path.exists(file_path):
                os.remove(file_path)

    @staticmethod
    def _require_file(path: str, label: str) -> bool:
        if os.path.isfile(path):
            return True
        logger.error(f"Required artifact missing: {label} ({path})")
        return False

    @staticmethod
    def _require_dir(path: str, label: str) -> bool:
        if os.path.isdir(path):
            return True
        logger.error(f"Required artifact missing: {label} ({path})")
        return False

    # ------------------------------------------------------------------
    # Clangd workspace setup
    # ------------------------------------------------------------------

    def _setup_clangd_workspace(self) -> bool:
        """Require the run-frozen compilation database used by all AST tools."""
        if not self.compile_commands_path or not os.path.isfile(
            self.compile_commands_path
        ):
            logger.error("Run-frozen compile_commands.json is missing")
            return False
        current = Path(self.library_root) / "build_analysis" / "compile_commands.json"
        frozen = Path(self.compile_commands_path)
        if not _same_compilation_database(current, frozen):
            logger.error(
                "build_analysis compile_commands.json differs from the run snapshot"
            )
            return False
        logger.success(
            f"Clangd compilation database ready: {self.compile_commands_path}"
        )
        return True

    def _build_library_variants(self) -> bool:
        """Build sanitizer and coverage variants when their artifacts are absent."""
        sanitize_ok = self._build_library_variant(
            "sanitize", "sanitize_library", "Sanitizer"
        )
        coverage_ok = self._build_library_variant(
            "coverage", "coverage_library", "Coverage"
        )
        return sanitize_ok and coverage_ok

    def _build_library_variant(self, mode: str, artifact_key: str, label: str) -> bool:
        """Build one configured library variant when its artifact is absent."""
        configured_path = self.config["compile_config"][artifact_key]
        if not configured_path:
            logger.error(f"{artifact_key} is not configured for {self.library_name}")
            return False

        artifact_path = configured_path
        if not os.path.isabs(artifact_path):
            artifact_path = os.path.join(str(get_project_root()), artifact_path)

        if not os.path.exists(self.build_script):
            logger.error(f"Build script not found: {self.build_script}")
            return False

        logger.info(f"Building {label.lower()} version of {self.library_name}...")

        try:
            result = subprocess.run(
                ["bash", self.build_script, mode],
                cwd=f"test_lib/{self.library_name}",
                capture_output=True,
                text=True,
            )

            if result.returncode == 0 and os.path.isfile(artifact_path):
                logger.success(f"{label} library built successfully: {artifact_path}")
                return True

            if result.returncode == 0:
                logger.error(f"Build completed without producing {artifact_path}")
                return False

            logger.error(f"Failed to build {label.lower()} library:")
            logger.error(f"STDOUT: {result.stdout}")
            logger.error(f"STDERR: {result.stderr}")
            return False

        except Exception as e:
            logger.error(f"Build failed with exception: {e}")
            return False

    # ------------------------------------------------------------------
    # Static extraction steps
    # ------------------------------------------------------------------

    def _extract_public_api(self, store: RunArtifactStore) -> bool:
        """Derive the API from the frozen analysis library and installed headers."""
        contract = store.read_json("stages/scan/build-result.json")
        if not isinstance(contract, dict) or contract.get("schema_version") != 1:
            logger.error("Invalid scan build contract")
            return False

        try:
            library = store.safe_path(contract["analysis_library"])
            headers_root = store.safe_path(contract["public_headers_root"])
            expected_library_hash = contract["analysis_library_sha256"]
            header_records = contract["public_headers"]
        except (KeyError, TypeError, ValueError) as exc:
            logger.error(f"Incomplete scan build contract: {exc}")
            return False
        if not library.is_file() or not headers_root.is_dir():
            logger.error("Frozen analysis library or public headers are missing")
            return False
        if _sha256(library) != expected_library_hash:
            logger.error("Frozen analysis library hash does not match build contract")
            return False
        if not isinstance(header_records, list) or not header_records:
            logger.error("Scan build contract contains no public headers")
            return False

        expected_headers = set()
        for record in header_records:
            if not isinstance(record, dict):
                logger.error("Invalid public header record in scan build contract")
                return False
            try:
                header = store.safe_path(record["path"])
                expected_hash = record["sha256"]
            except (KeyError, TypeError, ValueError) as exc:
                logger.error(f"Invalid public header record: {exc}")
                return False
            if not header.is_file() or _sha256(header) != expected_hash:
                logger.error(f"Frozen public header failed hash validation: {header}")
                return False
            expected_headers.add(header.resolve())

        actual_headers = {
            path.resolve()
            for path in headers_root.rglob("*")
            if path.is_file()
        }
        if actual_headers != expected_headers:
            logger.error("Frozen public header set does not match build contract")
            return False

        public_api_path = Path(self.info_lib_dir) / "api" / "public_api.json"
        public_api_config = self.config.get("public_api", {})
        try:
            result = extract_public_api(
                library,
                headers_root,
                self.config["language"],
                public_api_path,
                entry_headers=public_api_config.get("entry_headers"),
                include_dirs=public_api_config.get("include_dirs"),
                c_standard=public_api_config.get("c_standard", "c11"),
                cpp_standard=public_api_config.get("cpp_standard", "c++17"),
                include_transitive_declarations=public_api_config.get(
                    "include_transitive_declarations", True
                ),
            )
        except (OSError, RuntimeError, ValueError) as exc:
            logger.error(f"Public API extraction failed: {exc}")
            return False

        apis = result.get("apis") if isinstance(result, dict) else None
        if not isinstance(apis, list) or not apis:
            logger.error("Public API extraction produced no APIs")
            return False
        symbols = sorted(api["abi_symbol"] for api in apis)
        names = sorted(api["display_name"] for api in apis)
        Path(self.api_list_file).write_text("\n".join(names) + "\n", encoding="utf-8")
        Path(self.txt_dir, "api_symbols.txt").write_text(
            "\n".join(symbols) + "\n",
            encoding="utf-8",
        )
        logger.success(
            f"Extracted {len(apis)} installed public APIs -> {public_api_path}"
        )
        return True

    def _build_api_declarations(self) -> bool:
        """Write driver-facing declarations from the installed public interface."""
        out_file = f"{self.csv_dir}/api_declarations.csv"
        try:
            stats = build_public_api_declarations(
                self.library_name,
                Path(self.info_lib_dir) / "api" / "public_api.json",
            )
            logger.success(
                f"api_declarations.csv: {stats['with_header']}/{stats['api_count']} APIs with header "
                f"-> {stats['output']}"
            )
            return self._require_file(out_file, "api_declarations.csv")
        except Exception as exc:
            logger.error(f"api_declarations extraction failed: {exc}")
            return False
    # ------------------------------------------------------------------
    # Analysis steps
    # ------------------------------------------------------------------

    def _build_candidate_plan(self, store: RunArtifactStore) -> bool:
        """Materialize ABI graphs and rank all API candidates per target."""
        scan_root = store.safe_path("stages/scan/reachability")
        contract = store.read_json("stages/scan/build-result.json")
        analysis_library = store.safe_path(contract["analysis_library"])
        abi_dir = Path(self.callgraph_dir)
        try:
            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "src.preprocess.reachability.graph_materializer",
                    "--strict",
                    str(scan_root / "provenance-edges.jsonl"),
                    "--direct-graph",
                    str(scan_root / "call_graph.direct.csv"),
                    "--analysis-library",
                    str(analysis_library),
                    "--function-locations",
                    str(scan_root / "function_locations.csv"),
                    "--source-root",
                    self.library_root,
                    "--compile-commands",
                    self.compile_commands_path,
                    "--output-dir",
                    str(abi_dir),
                ],
                cwd=get_project_root(),
                check=True,
                stdout=subprocess.DEVNULL,
            )
            shutil.copy2(
                scan_root / "function_locations.csv",
                Path(self.csv_dir) / "function_locations.csv",
            )
            output = Path(self.info_lib_dir) / "targets" / "candidate_plan.json"
            plan = CandidatePlanBuilder(
                library=self.library_name,
                source_root=Path(self.library_root),
                targets_file=Path(self.targets_txt),
                compile_commands=Path(self.compile_commands_path),
                function_locations=scan_root / "function_locations.csv",
                graph_high=abi_dir / "call_graph.high.csv",
                graph_all=abi_dir / "call_graph.all.csv",
                public_api=Path(self.info_lib_dir) / "api" / "public_api.json",
            ).build(output)
        except (OSError, subprocess.SubprocessError, ValueError) as exc:
            logger.error(f"API-target candidate planning failed: {exc}")
            return False

        for dropped in plan["excluded_targets"]:
            logger.warning(
                "Dropped {} ({}): {}", dropped["marker"], dropped["target_id"], dropped["reason"]
            )
        if not any(target["candidates"] for target in plan["targets"]):
            logger.error("No target has a reachable public API candidate")
            return False
        logger.success(
            "Candidate plan: {} initial drivers, {} preserved API-target pairs, "
            "{} unresolved targets",
            plan["summary"]["initial_driver_count"],
            plan["summary"]["preserved_api_target_candidates"],
            plan["summary"]["unresolved"],
        )
        return True

    def _extract_api_ports(self) -> bool:
        """Enumerate per-function ports and produce/consume facts via libclang AST."""
        ports_file = f"{self.info_lib_dir}/raw/classify/api_ports.json"
        try:
            ports = PortExtractor(
                self.library_name,
                compile_commands_path=Path(self.compile_commands_path),
                force_recompute=True,
            ).extract()
            expected = {
                line.strip()
                for line in Path(self.txt_dir, "api_symbols.txt")
                .read_text(encoding="utf-8")
                .splitlines()
                if line.strip()
            }
            actual = set(ports)
            if actual != expected:
                missing = sorted(expected - actual)
                unexpected = sorted(actual - expected)
                raise ValueError(
                    "API port symbol set mismatch; "
                    f"missing={missing}, unexpected={unexpected}"
                )
        except Exception as exc:
            logger.error(f"API port extraction failed: {exc}")
            return False
        return self._require_file(ports_file, "api_ports.json")

    # ------------------------------------------------------------------
    # LLM + index steps
    # ------------------------------------------------------------------

    def _generate_api_docs(self, store: RunArtifactStore) -> bool:
        """Generate LLM-driven per-API documentation."""
        public_api_path = Path(self.info_lib_dir) / "api" / "public_api.json"
        public_api = json.loads(public_api_path.read_text(encoding="utf-8"))
        api_ids = [api["api_id"] for api in public_api.get("apis", [])]
        if not api_ids or len(api_ids) != len(set(api_ids)):
            logger.error("Public API identities are empty or duplicated")
            return False

        expected_index = {
            api_id: f"stages/preprocess/api-docs/{index:06d}.json"
            for index, api_id in enumerate(sorted(api_ids), 1)
        }
        index_path = store.safe_path("stages/preprocess/api-doc-index.json")
        if index_path.exists():
            if store.read_json(index_path) != expected_index:
                logger.error("Existing API document index does not match the API list")
                return False
        else:
            store.write_json("stages/preprocess/api-doc-index.json", expected_index)

        logger.info("Generating API documentation with LLM...")
        try:
            self.api_doc_stats = generate_all_lsp(
                self.library_name,
                store,
                expected_index,
                concurrency=self.concurrency,
            )
            logger.success(f"API documentation generated in {self.docs_dir}")
            return self._require_dir(self.docs_dir, "API docs directory")
        except Exception as e:
            logger.error(f"Failed to generate API docs: {e}")
            return False

    def _build_fact_base(self, store: RunArtifactStore) -> bool:
        """Merge api_ports.json (structural) + api/docs/*.json (semantic) into
        info_lib/<lib>/api/fact_base.json — the queryable API fact base."""
        ports = f"{self.info_lib_dir}/raw/classify/api_ports.json"
        out_file = f"{self.info_lib_dir}/api/fact_base.json"
        if not os.path.exists(ports) or not os.path.exists(self.docs_dir):
            logger.error("api_ports.json or docs missing, cannot build fact base")
            return False
        try:
            summary = build_fact_base(self.library_name, store)
            logger.success(
                f"Fact base built: {summary['api_count']} APIs "
                f"({summary['with_doc']} with docs) -> {summary['output']}"
            )
            return self._require_file(out_file, "fact_base.json")
        except Exception as e:
            logger.error(f"Fact base build failed: {e}")
            return False

    def _build_driver_corpus(self) -> bool:
        """Collect the library's bundled fuzz driver sources ->
        info_lib/<lib>/drivers.json (example templates for the generator)."""
        try:
            summary = build_driver_corpus(self.library_name)
            logger.success(
                f"Driver corpus: {summary['driver_count']} source fuzzers -> {summary['output']}"
            )
            return self._require_file(summary["output"], "drivers.json")
        except Exception as e:
            logger.error(f"Driver corpus build failed: {e}")
            return False

    def _build_vector_index(self, store: RunArtifactStore) -> bool:
        """Build the FAISS index over per-API docs."""
        if not os.path.exists(self.docs_dir):
            logger.error(f"API docs directory not found: {self.docs_dir}")
            return False
        try:
            build_vector_index(self.library_name, store)
        except Exception as exc:
            logger.error(f"FAISS index build failed: {exc}")
            return False
        index_dir = f"{self.info_lib_dir}/api/faiss_index"
        return all(
            self._require_file(f"{index_dir}/{name}", name)
            for name in ("index.faiss", "index.pkl")
        )
