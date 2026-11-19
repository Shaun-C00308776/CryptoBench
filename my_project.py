            # This line supplies an argument or value to the operation started above.
            "ECDH-P-256",
            # Creates a small function to pass into the benchmark runner.
            lambda: benchmark_ecdh(ec.SECP256R1(), "ECDH-P-256"),
        # Closes the function call or grouped expression started above.
        )
        # Starts the requested benchmark and sends its results to the shared measurement process.
        run_optional_benchmark(
            # This line supplies an argument or value to the operation started above.
            "ECDH-P-384",
            # Creates a small function to pass into the benchmark runner.
            lambda: benchmark_ecdh(ec.SECP384R1(), "ECDH-P-384"),
        # Closes the function call or grouped expression started above.
        )
        # Starts the requested benchmark and sends its results to the shared measurement process.
        run_optional_benchmark(
            # This line supplies an argument or value to the operation started above.
            "ECDH-P-521",
            # Creates a small function to pass into the benchmark runner.
            lambda: benchmark_ecdh(ec.SECP521R1(), "ECDH-P-521"),
        # Closes the function call or grouped expression started above.
        )
        # Starts the requested benchmark and sends its results to the shared measurement process.
        run_optional_benchmark("X25519", benchmark_x25519)
        # Starts the requested benchmark and sends its results to the shared measurement process.
        run_optional_benchmark("ML-KEM-768", lambda: benchmark_mlkem(768))
        # Starts the requested benchmark and sends its results to the shared measurement process.
        run_optional_benchmark("ML-KEM-1024", lambda: benchmark_mlkem(1024))

        # DIGITAL SIGNATURES
        # Starts the requested benchmark and sends its results to the shared measurement process.
        run_optional_benchmark(
            # This line supplies an argument or value to the operation started above.
            "RSA-PSS-3072", lambda: benchmark_rsa_signature(3072)
        # Closes the function call or grouped expression started above.
        )
        # Starts the requested benchmark and sends its results to the shared measurement process.
        run_optional_benchmark(
            # This line supplies an argument or value to the operation started above.
            "RSA-PSS-7680", lambda: benchmark_rsa_signature(7680)
        # Closes the function call or grouped expression started above.
        )
        # Starts the requested benchmark and sends its results to the shared measurement process.
        run_optional_benchmark(
            # This line supplies an argument or value to the operation started above.
            "ECDSA-P-256",
            # Creates a small function to pass into the benchmark runner.
            lambda: benchmark_ecdsa_signature(
                # This line supplies an argument or value to the operation started above.
                ec.SECP256R1(), "ECDSA-P-256", hashes.SHA256()
            # Closes the function call or grouped expression started above.
            ),
        # Closes the function call or grouped expression started above.
        )
        # Starts the requested benchmark and sends its results to the shared measurement process.
        run_optional_benchmark(
            # This line supplies an argument or value to the operation started above.
            "ECDSA-P-384",
            # Creates a small function to pass into the benchmark runner.
            lambda: benchmark_ecdsa_signature(
                # This line supplies an argument or value to the operation started above.
                ec.SECP384R1(), "ECDSA-P-384", hashes.SHA384()
            # Closes the function call or grouped expression started above.
            ),
        # Closes the function call or grouped expression started above.
        )
        # Starts the requested benchmark and sends its results to the shared measurement process.
        run_optional_benchmark(
            # This line supplies an argument or value to the operation started above.
            "ECDSA-P-521",
            # Creates a small function to pass into the benchmark runner.
            lambda: benchmark_ecdsa_signature(
                # This line supplies an argument or value to the operation started above.
                ec.SECP521R1(), "ECDSA-P-521", hashes.SHA512()
            # Closes the function call or grouped expression started above.
            ),
        # Closes the function call or grouped expression started above.
        )
        # Starts the requested benchmark and sends its results to the shared measurement process.
        run_optional_benchmark("Ed25519", benchmark_ed25519)
        # Starts the requested benchmark and sends its results to the shared measurement process.
        run_optional_benchmark("ML-DSA-44", lambda: benchmark_mldsa(44))
        # Starts the requested benchmark and sends its results to the shared measurement process.
        run_optional_benchmark("ML-DSA-65", lambda: benchmark_mldsa(65))
        # Starts the requested benchmark and sends its results to the shared measurement process.
        run_optional_benchmark("ML-DSA-87", lambda: benchmark_mldsa(87))

        # AUTHENTICATED ENCRYPTION
        # Starts the requested benchmark and sends its results to the shared measurement process.
        run_optional_benchmark(
            # This line supplies an argument or value to the operation started above.
            "AES-128-GCM",
            # Creates a small function to pass into the benchmark runner.
            lambda: benchmark_aead_algorithm("AES-128-GCM", AESGCM, 16),
        # Closes the function call or grouped expression started above.
        )
        # Starts the requested benchmark and sends its results to the shared measurement process.
        run_optional_benchmark(
            # This line supplies an argument or value to the operation started above.
            "AES-256-GCM",
            # Creates a small function to pass into the benchmark runner.
            lambda: benchmark_aead_algorithm("AES-256-GCM", AESGCM, 32),
        # Closes the function call or grouped expression started above.
        )
        # Starts the requested benchmark and sends its results to the shared measurement process.
        run_optional_benchmark(
            # This line supplies an argument or value to the operation started above.
            "ChaCha20-Poly1305",
            # Creates a small function to pass into the benchmark runner.
            lambda: benchmark_aead_algorithm(
                # This line supplies an argument or value to the operation started above.
                "ChaCha20-Poly1305", ChaCha20Poly1305, 32
            # Closes the function call or grouped expression started above.
            ),
        # Closes the function call or grouped expression started above.
        )

        # Defines a function; the name and parameters describe the task and inputs it handles.
        def benchmark_aes_gcm_siv():
            # Imports the required cryptography or utility feature from cryptography.hazmat.primitives.ciphers.aead.
            from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV
            # Runs the named cryptographic benchmark.
            benchmark_aead_algorithm("AES-256-GCM-SIV", AESGCMSIV, 32)

        # Starts the requested benchmark and sends its results to the shared measurement process.
        run_optional_benchmark("AES-256-GCM-SIV", benchmark_aes_gcm_siv)

    # Runs this cleanup block whether the protected code succeeds or fails.
    finally:
        # Save anything measured even if an unexpected error stops the run.
        # Saves all recorded measurements to the CSV output file.
        save_results(args.output_directory)

    # Displays this information in the terminal.
    print("\nBenchmark run finished.")
    # Displays this information in the terminal.
    print("Check the terminal for any algorithms marked SKIPPED.")
    # Displays this information in the terminal.
    print("Do not edit raw.csv: it must contain the actual measured results.")


# Runs the program entry point only when this file is executed directly.
if __name__ == "__main__":
    # This line supplies an argument or value to the operation started above.
    main()

