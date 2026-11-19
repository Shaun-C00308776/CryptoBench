
import os
import csv
import time
import statistics
import argparse

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding


# Store all measurements
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


# Benchmark RSA-OAEP
def benchmark_rsa_oaep(key_size):

    algorithm = "RSA-OAEP-" + str(key_size)

    print("\nTesting", algorithm)

    # Generate RSA keys (21 measurements)
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

    # Generate one key pair for other operations
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size
    )

    public_key = private_key.public_key()

    # Configure OAEP padding
    oaep = padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )

    # Encapsulation
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

    # Create ciphertext before measuring decapsulation
    secret = os.urandom(32)

    ciphertext = public_key.encrypt(secret, oaep)

    # Decapsulation
    def decapsulate():

        recovered_secret = private_key.decrypt(
            ciphertext,
            oaep
        )

    decapsulate_times = measure(
        "kem",
        algorithm,
        "decapsulate",
        0,
        decapsulate
    )

    # Display statistics
    print("\nStatistics for", algorithm)

    for operation, times in [
        ("Key generation", keygen_times),
        ("Encapsulation", encapsulate_times),
        ("Decapsulation", decapsulate_times)
    ]:

        median, iqr = calculate_statistics(times)

        print(operation)
        print("Median:", median / 1_000_000, "ms")
        print("IQR:", iqr / 1_000_000, "ms")

    print("\n", algorithm, "completed!")


# Main program
def main():

    parser = argparse.ArgumentParser()

    parser.add_argument("output_folder")

    args = parser.parse_args()

    print("================================")
    print("       CryptoBench Project")
    print("================================")

    # KEY ESTABLISHMENT

    print("\nKEY ESTABLISHMENT")

    benchmark_rsa_oaep(3072)

    benchmark_rsa_oaep(7680)

    # Save all measurements
    save_results(args.output_folder)

    print("\n================================")
    print("       Project completed!")
    print("================================")


if __name__ == "__main__":
    main()
