
import os
import sys
import csv
import time
import statistics
import argparse

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import (
    rsa,
    ec,
    x25519,
    padding,
    ed25519
)

from cryptography.hazmat.primitives.ciphers.aead import (
    AESGCM,
    AESGCMSIV,
    ChaCha20Poly1305
)

from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# Store all measurements
results = []

# Measure how long an operation takes
def measure(part, algorithm, operation, message_bytes, function, runs=101):

    for run in range(runs):

        start = time.perf_counter_ns()

        function()

        end = time.perf_counter_ns()

        elapsed = end - start

        results.append([
            part,
            algorithm,
            operation,
            message_bytes,
            run,
            elapsed
        ])

    print("Completed:", algorithm, operation)


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

    print("Results saved to:", filename)


# Main program
def main():

    parser = argparse.ArgumentParser()

    parser.add_argument("output_folder")

    args = parser.parse_args()

    print("Starting CryptoBench...")

    # Benchmark sections will go here

    save_results(args.output_folder)

    print("CryptoBench completed!")


if __name__ == "__main__":
    main()

