"""Fixed sanitizer policy shared by every fuzz target."""

FUZZ_INPUT_TIMEOUT_SECONDS = 25
FUZZ_RSS_LIMIT_MB = 2560

ASAN_OPTIONS = ":".join(
    (
        "alloc_dealloc_mismatch=0",
        "allocator_may_return_null=1",
        "allocator_release_to_os_interval_ms=500",
        "check_malloc_usable_size=0",
        "detect_container_overflow=1",
        "detect_odr_violation=0",
        "detect_leaks=1",
        "detect_stack_use_after_return=1",
        "fast_unwind_on_fatal=0",
        "handle_abort=1",
        "handle_segv=1",
        "handle_sigill=1",
        "max_uar_stack_size_log=16",
        "print_scariness=1",
        "quarantine_size_mb=10",
        "strict_memcmp=1",
        "strip_path_prefix=/workspace/",
        "symbolize=1",
        "use_sigaltstack=1",
        "dedup_token_length=3",
    )
)

UBSAN_OPTIONS = ":".join(
    (
        "print_stacktrace=1",
        "print_summary=1",
        "silence_unsigned_overflow=1",
        "strip_path_prefix=/workspace/",
        "symbolize=1",
        "dedup_token_length=3",
        "halt_on_error=1",
    )
)
