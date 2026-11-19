
import os
import csv
import time
import statistics
import argparse

from cryptography.exceptions import UnsupportedAlgorithm

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization

from cryptography.hazmat.primitives.asymmetric import (
    rsa,
    padding,
    ec,
    x25519,
    mlkem
)


results = []


# Measure how long an operation takes
def measure(part, algorithm, operation, message_bytes, function, runs=101):

    times = []

    for run in range(runs):

        start = time.perf_counter_ns()

        function()

        end = time.perf_counter_ns()

        elapsed = end - start

        times.append(elapsed)

        results.append([
            part,
            algorithm,
            operation,
            message_bytes,
            run,
            elapsed
        ])

    print("Completed:", algorithm, operation)

    return times


# Calculate median and IQR
def calculate_statistics(times):

    measurements = times[1:]

    median = statistics.median(measurements)

    quartiles = statistics.quantiles(measurements, n=4)

    iqr = quartiles[2] - quartiles[0]

    return median, iqr


# Display statistics
def display_statistics(algorithm, operations):

    print("\nStatistics for", algorithm)

    for operation, times in operations:

        median, iqr = calculate_statistics(times)

        print(operation)

        print("Median:", median / 1_000_000, "ms")

        print("IQR:", iqr / 1_000_000, "ms")


# Save measurements to CSV
def save_results(output_folder):

    os.makedirs(output_folder, exist_ok=True)

    filename = os.path.join(output_folder, "raw.csv")

    with open(filename, "w", newline="") as file:

        writer = csv.writer(file)

        writer.writerow([
            "part",
            "algorithm",
            "operation",
            "message_bytes",
            "run",
            "nanoseconds"
        ])

        writer.writerows(results)

    print("\nResults saved to:", filename)


# ==================================================
# RSA-OAEP
# ==================================================

def benchmark_rsa_oaep(key_size):

    algorithm = "RSA-OAEP-" + str(key_size)

    print("\nTesting", algorithm)

    keygen_times = measure(
        "kem",
        algorithm,
        "keygen",
        0,
        lambda: rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size
        ),
        runs=21
    )

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size
    )

    public_key = private_key.public_key()

    oaep = padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )

    def encapsulate():

        secret = os.urandom(32)

        public_key.encrypt(secret, oaep)

    encapsulate_times = measure(
        "kem",
        algorithm,
        "encapsulate",
        0,
        encapsulate
    )

    secret = os.urandom(32)

    ciphertext = public_key.encrypt(secret, oaep)

    def decapsulate():

        private_key.decrypt(ciphertext, oaep)

    decapsulate_times = measure(
        "kem",
        algorithm,
        "decapsulate",
        0,
        decapsulate
    )

    display_statistics(
        algorithm,
        [
            ("Key generation", keygen_times),
            ("Encapsulation", encapsulate_times),
            ("Decapsulation", decapsulate_times)
        ]
    )


# ==================================================
# ECDH
# ==================================================

def benchmark_ecdh(curve, algorithm):

    print("\nTesting", algorithm)

    keygen_times = measure(
        "kem",
        algorithm,
        "keygen",
        0,
        lambda: ec.generate_private_key(curve)
    )

    # Generate receiver key pair outside timing
    private_key = ec.generate_private_key(curve)

    public_key = private_key.public_key()

    # Generate one ephemeral key pair for decapsulation
    ephemeral_private = ec.generate_private_key(curve)

    ephemeral_public = ephemeral_private.public_key()

    # Convert ephemeral public key into ciphertext bytes
    ciphertext = ephemeral_public.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )

    # Check that both parties generate the same secret
    sender_secret = ephemeral_private.exchange(
        ec.ECDH(),
        public_key
    )

    receiver_secret = private_key.exchange(
        ec.ECDH(),
        ephemeral_public
    )

    assert sender_secret == receiver_secret

    # Encapsulation
    def encapsulate():

        new_ephemeral = ec.generate_private_key(curve)

        new_secret = new_ephemeral.exchange(
            ec.ECDH(),
            public_key
        )

        new_ephemeral.public_key().public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )

    encapsulate_times = measure(
        "kem",
        algorithm,
        "encapsulate",
        0,
        encapsulate
    )

    # Decapsulation
    def decapsulate():

        loaded_public_key = ec.EllipticCurvePublicKey.from_encoded_point(
            curve,
            ciphertext
        )

        private_key.exchange(
            ec.ECDH(),
            loaded_public_key
        )

    decapsulate_times = measure(
        "kem",
        algorithm,
        "decapsulate",
        0,
        decapsulate
    )

    display_statistics(
        algorithm,
        [
            ("Key generation", keygen_times),
            ("Encapsulation", encapsulate_times),
            ("Decapsulation", decapsulate_times)
        ]
    )


# ==================================================
# X25519
# ==================================================

def benchmark_x25519():

    algorithm = "X25519"

    print("\nTesting", algorithm)

    keygen_times = measure(
        "kem",
        algorithm,
        "keygen",
        0,
        lambda: x25519.X25519PrivateKey.generate()
    )

    # Generate receiver key pair
    private_key = x25519.X25519PrivateKey.generate()

    public_key = private_key.public_key()

    # Generate ephemeral key pair for decapsulation
    ephemeral_private = x25519.X25519PrivateKey.generate()

    ephemeral_public = ephemeral_private.public_key()

    # Convert public key into ciphertext bytes
    ciphertext = ephemeral_public.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )

    # Check shared secrets match
    sender_secret = ephemeral_private.exchange(public_key)

    receiver_secret = private_key.exchange(ephemeral_public)

    assert sender_secret == receiver_secret

    # Encapsulation
    def encapsulate():

        new_ephemeral = x25519.X25519PrivateKey.generate()

        new_secret = new_ephemeral.exchange(public_key)

        new_ephemeral.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

    encapsulate_times = measure(
        "kem",
        algorithm,
        "encapsulate",
        0,
        encapsulate
    )

    # Decapsulation
    def decapsulate():

        loaded_public_key = x25519.X25519PublicKey.from_public_bytes(
            ciphertext
        )

        private_key.exchange(loaded_public_key)

    decapsulate_times = measure(
        "kem",
        algorithm,
        "decapsulate",
        0,
        decapsulate
    )

    display_statistics(
        algorithm,
        [
            ("Key generation", keygen_times),
            ("Encapsulation", encapsulate_times),
            ("Decapsulation", decapsulate_times)
        ]
    )


# ==================================================
# ML-KEM
# ==================================================

def benchmark_mlkem(key_size):

    algorithm = "ML-KEM-" + str(key_size)

    print("\nTesting", algorithm)

    if key_size == 768:

        key_class = mlkem.MLKEM768PrivateKey

    elif key_size == 1024:

        key_class = mlkem.MLKEM1024PrivateKey

    else:

        raise ValueError("Unsupported ML-KEM key size")

    # Key generation
    keygen_times = measure(
        "kem",
        algorithm,
        "keygen",
        0,
        lambda: key_class.generate()
    )

    # Generate one key pair for other operations
    private_key = key_class.generate()

    public_key = private_key.public_key()

    # Generate ciphertext and secret before timing
    shared_secret, ciphertext = public_key.encapsulate()

    # Check that decapsulation recovers the same secret
    recovered_secret = private_key.decapsulate(ciphertext)

    assert shared_secret == recovered_secret

    # Encapsulation
    def encapsulate():

        public_key.encapsulate()

    encapsulate_times = measure(
        "kem",
        algorithm,
        "encapsulate",
        0,
        encapsulate
    )

    # Decapsulation
    def decapsulate():

        private_key.decapsulate(ciphertext)

    decapsulate_times = measure(
        "kem",
        algorithm,
        "decapsulate",
        0,
        decapsulate
    )

    display_statistics(
        algorithm,
        [
            ("Key generation", keygen_times),
            ("Encapsulation", encapsulate_times),
            ("Decapsulation", decapsulate_times)
        ]
    )


# ==================================================
# MAIN PROGRAM
# ==================================================

def main():

    parser = argparse.ArgumentParser()

    parser.add_argument("output_folder")

    args = parser.parse_args()

    print("================================")
    print("       CryptoBench Project")
    print("================================")

    try:

        # RSA-OAEP
        print("\nKEY ESTABLISHMENT - RSA")

        benchmark_rsa_oaep(3072)

        benchmark_rsa_oaep(7680)

        # ECDH
        print("\nKEY ESTABLISHMENT - ECDH")

        benchmark_ecdh(
            ec.SECP256R1(),
            "ECDH-P-256"
        )

        benchmark_ecdh(
            ec.SECP384R1(),
            "ECDH-P-384"
        )

        benchmark_ecdh(
            ec.SECP521R1(),
            "ECDH-P-521"
        )

        # X25519
        print("\nKEY ESTABLISHMENT - X25519")

        benchmark_x25519()

        # ML-KEM
        print("\nKEY ESTABLISHMENT - ML-KEM")

        benchmark_mlkem(768)

        benchmark_mlkem(1024)

    except UnsupportedAlgorithm as error:

        print("\nERROR: A cryptographic algorithm is not supported.")
        print(error)

    finally:

        save_results(args.output_folder)

    print("\n================================")
    print("       Project completed!")
    print("================================")


if __name__ == "__main__":
    main()
