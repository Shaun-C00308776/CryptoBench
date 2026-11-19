import argparse
import csv
import os
import platform
import ssl
import statistics
import sys
import time
from pathlib import Path

import cryptography
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import (
    ec,
    ed25519,
    padding,
    rsa,
    x25519,
)
from cryptography.hazmat.primitives.ciphers.aead import (
    AESGCM,
    ChaCha20Poly1305,
)


CSV_HEADER = [
    "part",
    "algorithm",
    "operation",
    "message_bytes",
    "run",
    "nanoseconds",
]

RUNS = 101
RSA_KEYGEN_RUNS = 21
AEAD_MESSAGE_SIZES = [64, 1024, 16384, 1048576]

results = []
signature_message = os.urandom(1024)


def measure(part, algorithm, operation, function, message_bytes=0, runs=RUNS):
    """Time one operation repeatedly and save every result, including run 0."""
    times = []

    for run_number in range(runs):
        start = time.perf_counter_ns()
        function()
        end = time.perf_counter_ns()

        elapsed = end - start
        times.append(elapsed)

        results.append({
            "part": part,
            "algorithm": algorithm,
            "operation": operation,
            "message_bytes": message_bytes,
            "run": run_number,
            "nanoseconds": elapsed,
        })

    return times


def calculate_statistics(times):
    """Calculate median and IQR after removing the warm-up run."""
    measured_times = times[1:]

    median_ns = statistics.median(measured_times)
    quartiles = statistics.quantiles(measured_times, n=4)
    iqr_ns = quartiles[2] - quartiles[0]

    return median_ns / 1_000_000, iqr_ns / 1_000_000


def display_statistics(algorithm, operation, times):
    median_ms, iqr_ms = calculate_statistics(times)
    print(
        f"  {algorithm:<22} {operation:<12} "
        f"median={median_ms:.4f} ms, IQR={iqr_ms:.4f} ms"
    )


def run_measurement(part, algorithm, operation, function,
                    message_bytes=0, runs=RUNS):
    times = measure(
        part,
        algorithm,
        operation,
        function,
        message_bytes,
        runs,
    )
    display_statistics(algorithm, operation, times)


def save_results(output_directory):
    """Write all recorded measurements to the required CSV file."""
    output_path = Path(output_directory)
    output_path.mkdir(parents=True, exist_ok=True)
    csv_path = output_path / "raw.csv"

    with csv_path.open("w", newline="", encoding="utf-8") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=CSV_HEADER)
        writer.writeheader()
        writer.writerows(results)

    print(f"\nCSV saved to: {csv_path.resolve()}")
    print(f"Rows written (including warm-ups): {len(results)}")


def show_environment():
    print("CryptoBench environment")
    print("-----------------------")
    print(f"Operating system: {platform.platform()}")
    print(f"Machine: {platform.machine()}")
    print(f"Processor: {platform.processor() or 'Not reported by Python'}")
    print(f"Python: {sys.version.split()[0]}")
    print(f"cryptography: {cryptography.__version__}")
    print(f"OpenSSL: {ssl.OPENSSL_VERSION}")
    print()


def benchmark_rsa_oaep(key_size):
    algorithm = f"RSA-OAEP-{key_size}"
    print(f"\n{algorithm}")

    run_measurement(
        "kem",
        algorithm,
        "keygen",
        lambda: rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
        ),
        runs=RSA_KEYGEN_RUNS,
    )

    # One key pair is created outside the timing for all other operations.
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
    )
    public_key = private_key.public_key()

    oaep = padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    )

    def encapsulate():
        secret = os.urandom(32)
        public_key.encrypt(secret, oaep)

    secret = os.urandom(32)
    ciphertext = public_key.encrypt(secret, oaep)
    assert private_key.decrypt(ciphertext, oaep) == secret

    def decapsulate():
        private_key.decrypt(ciphertext, oaep)

    run_measurement("kem", algorithm, "encapsulate", encapsulate)
    run_measurement("kem", algorithm, "decapsulate", decapsulate)


def benchmark_ecdh(curve, algorithm):
    print(f"\n{algorithm}")

    run_measurement(
        "kem",
        algorithm,
        "keygen",
        lambda: ec.generate_private_key(curve),
    )

    # Reuse this receiver key pair for encapsulation and decapsulation.
    receiver_private = ec.generate_private_key(curve)
    receiver_public = receiver_private.public_key()

    # Prepare one fixed ephemeral public key for the decapsulation test.
    fixed_ephemeral_private = ec.generate_private_key(curve)
    fixed_ephemeral_public = fixed_ephemeral_private.public_key()
    fixed_ciphertext = fixed_ephemeral_public.public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint,
    )

    sender_secret = fixed_ephemeral_private.exchange(
        ec.ECDH(), receiver_public
    )
    receiver_secret = receiver_private.exchange(
        ec.ECDH(),
        ec.EllipticCurvePublicKey.from_encoded_point(curve, fixed_ciphertext),
    )
    assert sender_secret == receiver_secret

    def encapsulate():
        ephemeral_private = ec.generate_private_key(curve)
        ephemeral_private.exchange(ec.ECDH(), receiver_public)
        ephemeral_private.public_key().public_bytes(
            serialization.Encoding.X962,
            serialization.PublicFormat.UncompressedPoint,
        )

    def decapsulate():
        ephemeral_public = ec.EllipticCurvePublicKey.from_encoded_point(
            curve, fixed_ciphertext
        )
        receiver_private.exchange(ec.ECDH(), ephemeral_public)

    run_measurement("kem", algorithm, "encapsulate", encapsulate)
    run_measurement("kem", algorithm, "decapsulate", decapsulate)


def benchmark_x25519():
    algorithm = "X25519"
    print(f"\n{algorithm}")

    run_measurement(
        "kem",
        algorithm,
        "keygen",
        x25519.X25519PrivateKey.generate,
    )

    receiver_private = x25519.X25519PrivateKey.generate()
    receiver_public = receiver_private.public_key()

    fixed_ephemeral_private = x25519.X25519PrivateKey.generate()
    fixed_ciphertext = fixed_ephemeral_private.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )

    sender_secret = fixed_ephemeral_private.exchange(receiver_public)
    fixed_ephemeral_public = x25519.X25519PublicKey.from_public_bytes(
        fixed_ciphertext
    )
    receiver_secret = receiver_private.exchange(fixed_ephemeral_public)
    assert sender_secret == receiver_secret

    def encapsulate():
        ephemeral_private = x25519.X25519PrivateKey.generate()
        ephemeral_private.exchange(receiver_public)
        ephemeral_private.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )

    def decapsulate():
        ephemeral_public = x25519.X25519PublicKey.from_public_bytes(
            fixed_ciphertext
        )
        receiver_private.exchange(ephemeral_public)

    run_measurement("kem", algorithm, "encapsulate", encapsulate)
    run_measurement("kem", algorithm, "decapsulate", decapsulate)


def benchmark_mlkem(key_size):
    from cryptography.hazmat.primitives.asymmetric import mlkem

    algorithm = f"ML-KEM-{key_size}"
    print(f"\n{algorithm}")

    if key_size == 768:
        private_key_class = mlkem.MLKEM768PrivateKey
    else:
        private_key_class = mlkem.MLKEM1024PrivateKey

    run_measurement(
        "kem",
        algorithm,
        "keygen",
        private_key_class.generate,
    )

    private_key = private_key_class.generate()
    public_key = private_key.public_key()

    shared_secret, ciphertext = public_key.encapsulate()
    assert private_key.decapsulate(ciphertext) == shared_secret

    def encapsulate():
        public_key.encapsulate()

    def decapsulate():
        private_key.decapsulate(ciphertext)

    run_measurement("kem", algorithm, "encapsulate", encapsulate)
    run_measurement("kem", algorithm, "decapsulate", decapsulate)


def benchmark_rsa_signature(key_size):
    algorithm = f"RSA-PSS-{key_size}"
    print(f"\n{algorithm}")

    run_measurement(
        "signature",
        algorithm,
        "keygen",
        lambda: rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
        ),
        runs=RSA_KEYGEN_RUNS,
    )

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
    )
    public_key = private_key.public_key()

    pss = padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=hashes.SHA256().digest_size,
    )

    def sign():
        private_key.sign(signature_message, pss, hashes.SHA256())

    signature = private_key.sign(signature_message, pss, hashes.SHA256())

    def verify():
        public_key.verify(
            signature,
            signature_message,
            pss,
            hashes.SHA256(),
        )

    run_measurement("signature", algorithm, "sign", sign)
    run_measurement("signature", algorithm, "verify", verify)


def benchmark_ecdsa_signature(curve, algorithm, hash_algorithm):
    print(f"\n{algorithm}")

    run_measurement(
        "signature",
        algorithm,
        "keygen",
        lambda: ec.generate_private_key(curve),
    )

    private_key = ec.generate_private_key(curve)
    public_key = private_key.public_key()

    def sign():
        private_key.sign(
            signature_message,
            ec.ECDSA(hash_algorithm),
        )

    signature = private_key.sign(
        signature_message,
        ec.ECDSA(hash_algorithm),
    )

    def verify():
        public_key.verify(
            signature,
            signature_message,
            ec.ECDSA(hash_algorithm),
        )

    run_measurement("signature", algorithm, "sign", sign)
    run_measurement("signature", algorithm, "verify", verify)


def benchmark_ed25519():
    algorithm = "Ed25519"
    print(f"\n{algorithm}")

    run_measurement(
        "signature",
        algorithm,
        "keygen",
        ed25519.Ed25519PrivateKey.generate,
    )

    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    def sign():
        private_key.sign(signature_message)

    signature = private_key.sign(signature_message)

    def verify():
        public_key.verify(signature, signature_message)

    run_measurement("signature", algorithm, "sign", sign)
    run_measurement("signature", algorithm, "verify", verify)


def benchmark_mldsa(key_size):
    from cryptography.hazmat.primitives.asymmetric import mldsa

    algorithm = f"ML-DSA-{key_size}"
    print(f"\n{algorithm}")

    key_classes = {
        44: mldsa.MLDSA44PrivateKey,
        65: mldsa.MLDSA65PrivateKey,
        87: mldsa.MLDSA87PrivateKey,
    }
    private_key_class = key_classes[key_size]

    run_measurement(
        "signature",
        algorithm,
        "keygen",
        private_key_class.generate,
    )

    private_key = private_key_class.generate()
    public_key = private_key.public_key()

    def sign():
        private_key.sign(signature_message)

    signature = private_key.sign(signature_message)

    def verify():
        public_key.verify(signature, signature_message)

    run_measurement("signature", algorithm, "sign", sign)
    run_measurement("signature", algorithm, "verify", verify)


def benchmark_aead_algorithm(algorithm, cipher_class, key_size):
    print(f"\n{algorithm}")

    for message_size in AEAD_MESSAGE_SIZES:
        print(f"  Message size: {message_size} bytes")

        # Key and message are generated before timing.
        key = os.urandom(key_size)
        message = os.urandom(message_size)
        cipher = cipher_class(key)

        # Pre-generate a different nonce for each of the 101 encryptions.
        # This keeps nonce generation outside the timed section.
        nonces = [os.urandom(12) for _ in range(RUNS)]

        # Create the fixed ciphertext used for every decrypt measurement.
        fixed_ciphertext = cipher.encrypt(nonces[0], message, None)
        assert cipher.decrypt(nonces[0], fixed_ciphertext, None) == message

        nonce_index = 0

        def encrypt():
            nonlocal nonce_index
            cipher.encrypt(nonces[nonce_index], message, None)
            nonce_index += 1

        def decrypt():
            cipher.decrypt(nonces[0], fixed_ciphertext, None)

        run_measurement(
            "aead",
            algorithm,
            "encrypt",
            encrypt,
            message_bytes=message_size,
        )
        run_measurement(
            "aead",
            algorithm,
            "decrypt",
            decrypt,
            message_bytes=message_size,
        )


def run_optional_benchmark(label, function):
    """Continue to other algorithms if this OpenSSL build lacks one."""
    try:
        function()
    except (UnsupportedAlgorithm, ImportError, AttributeError, NotImplementedError) as error:
        print(f"\nSKIPPED {label}: this installation/backend does not support it.")
        print(f"Reason: {error}")


def main():
    parser = argparse.ArgumentParser(
        description="Benchmark the cryptographic algorithms in the SETU project."
    )
    parser.add_argument(
        "output_directory",
        help="Directory where raw.csv will be saved, e.g. results/run-1",
    )
    args = parser.parse_args()

    show_environment()
    print("Starting benchmarks. This may take a while, especially RSA key generation.")
    print("Please leave the computer alone while the measurements run.")

    try:
        # KEY ESTABLISHMENT
        run_optional_benchmark(
            "RSA-OAEP-3072", lambda: benchmark_rsa_oaep(3072)
        )
        run_optional_benchmark(
            "RSA-OAEP-7680", lambda: benchmark_rsa_oaep(7680)
        )
        run_optional_benchmark(
            "ECDH-P-256",
            lambda: benchmark_ecdh(ec.SECP256R1(), "ECDH-P-256"),
        )
        run_optional_benchmark(
            "ECDH-P-384",
            lambda: benchmark_ecdh(ec.SECP384R1(), "ECDH-P-384"),
        )
        run_optional_benchmark(
            "ECDH-P-521",
            lambda: benchmark_ecdh(ec.SECP521R1(), "ECDH-P-521"),
        )
        run_optional_benchmark("X25519", benchmark_x25519)
        run_optional_benchmark("ML-KEM-768", lambda: benchmark_mlkem(768))
        run_optional_benchmark("ML-KEM-1024", lambda: benchmark_mlkem(1024))

        # DIGITAL SIGNATURES
        run_optional_benchmark(
            "RSA-PSS-3072", lambda: benchmark_rsa_signature(3072)
        )
        run_optional_benchmark(
            "RSA-PSS-7680", lambda: benchmark_rsa_signature(7680)
        )
        run_optional_benchmark(
            "ECDSA-P-256",
            lambda: benchmark_ecdsa_signature(
                ec.SECP256R1(), "ECDSA-P-256", hashes.SHA256()
            ),
        )
        run_optional_benchmark(
            "ECDSA-P-384",
            lambda: benchmark_ecdsa_signature(
                ec.SECP384R1(), "ECDSA-P-384", hashes.SHA384()
            ),
        )
        run_optional_benchmark(
            "ECDSA-P-521",
            lambda: benchmark_ecdsa_signature(
                ec.SECP521R1(), "ECDSA-P-521", hashes.SHA512()
            ),
        )
        run_optional_benchmark("Ed25519", benchmark_ed25519)
        run_optional_benchmark("ML-DSA-44", lambda: benchmark_mldsa(44))
        run_optional_benchmark("ML-DSA-65", lambda: benchmark_mldsa(65))
        run_optional_benchmark("ML-DSA-87", lambda: benchmark_mldsa(87))

        # AUTHENTICATED ENCRYPTION
        run_optional_benchmark(
            "AES-128-GCM",
            lambda: benchmark_aead_algorithm("AES-128-GCM", AESGCM, 16),
        )
        run_optional_benchmark(
            "AES-256-GCM",
            lambda: benchmark_aead_algorithm("AES-256-GCM", AESGCM, 32),
        )
        run_optional_benchmark(
            "ChaCha20-Poly1305",
            lambda: benchmark_aead_algorithm(
                "ChaCha20-Poly1305", ChaCha20Poly1305, 32
            ),
        )

        def benchmark_aes_gcm_siv():
            from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV
            benchmark_aead_algorithm("AES-256-GCM-SIV", AESGCMSIV, 32)

        run_optional_benchmark("AES-256-GCM-SIV", benchmark_aes_gcm_siv)

    finally:
        # Save anything measured even if an unexpected error stops the run.
        save_results(args.output_directory)

    print("\nBenchmark run finished.")
    print("Check the terminal for any algorithms marked SKIPPED.")
    print("Do not edit raw.csv: it must contain the actual measured results.")


if __name__ == "__main__":
    main()
