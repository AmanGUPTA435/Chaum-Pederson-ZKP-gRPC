# ZKP gRPC client/server for authentication

## Local Run

You will need to install the rust on your machine and also the `protobuf-compiler`, for Linux:

```bash
sudo apt install protobuf-compiler
```

## Docker

You can run the program with Docker. First build the containers:

```
$ docker-compose build zkpserver
```

Run the container:

```
$ docker-compose run --rm zkpserver
```

In the remote terminal that appears run the server:

```
root@e84736012f9a:/zkp-server# cargo run --bin server --release
```

Open a new terminal on your machine and connect to the container:

```
$ docker container ls
CONTAINER ID   IMAGE                  COMMAND   CREATED          STATUS          PORTS     NAMES
e84736012f9a   zkp-course-zkpserver   "bash"    20 minutes ago   Up 20 minutes             zkp-course_zkpserver_run_b1f3fa2cd94a

$ docker exec -it e84736012f9a /bin/bash
```

Run the client:

```
root@e84736012f9a:/zkp-server# cargo run --bin client --release
```

![image](https://github.com/user-attachments/assets/77cbe475-68c6-4d04-89bd-a7de1ed27c13)

# Chaum-Pedersen Zero-Knowledge Proof Protocol

## Overview

The Chaum-Pedersen protocol is a zero-knowledge proof scheme that allows a prover to demonstrate knowledge of a secret \( x \), such that:

- \( Y_1 = g^x \)
- \( Y_2 = h^x \)

The protocol achieves this without revealing \( x \).

---

## Parameters

- **Prover (Client)**:
  - Holds the secret \( x \).
- **Verifier (Server)**:
  - Validates the proof of knowledge of \( x \).
- **Public Values**:
  - \( g, h \): Generators in a cyclic group.
  - \( Y_1 = g^x \), \( Y_2 = h^x \): Commitments.
- **Random Values**:
  - \( k \): Prover's random value.
  - \( c \): Verifier's random challenge.

---

## Protocol Steps

1. **Registration**:

   - Prover computes \( Y_1 = g^x \) and \( Y_2 = h^x \), and sends them to the verifier.

2. **Verification (Round 1)**:

   - Prover generates \( k \) and computes:
     \[
     R_1 = g^k, \quad R_2 = h^k
     \]
   - Sends \( R_1, R_2 \) to the verifier.

3. **Verification (Round 2)**:

   - Verifier generates a random challenge \( c \) and sends it to the prover.

4. **Verification (Round 3)**:

   - Prover computes:
     \[
     s = k - c \cdot x
     \]
   - Sends \( s \) to the verifier.

5. **Final Verification**:
   - Verifier checks:
     \[
     R_1 = g^s \cdot Y_1^c, \quad R_2 = h^s \cdot Y_2^c
     \]
   - If both conditions are satisfied, the proof is valid.

---

## Security Properties

- **Zero-Knowledge**: The verifier learns nothing about \( x \).
- **Soundness**: The prover cannot convince the verifier without knowing \( x \).
- **Completeness**: If the prover knows \( x \), the proof is always accepted.

---

## Applications

- Multi-party computation
- Cryptographic protocols (e.g., Digital Signatures, Mix-nets)
- Privacy-preserving systems

---

## Example

Suppose:

- \( g = 2 \), \( h = 3 \)
- Prover's secret \( x = 5 \)

### Registration:

- Compute \( Y_1 = g^x = 2^5 = 32 \), \( Y_2 = h^x = 3^5 = 243 \)

### Verification:

- **Round 1**:
  - Prover generates \( k = 7 \), computes:
    \[
    R_1 = g^k = 2^7 = 128, \quad R_2 = h^k = 3^7 = 2187
    \]
  - Sends \( R_1, R_2 \) to verifier.
- **Round 2**:
  - Verifier sends random \( c = 4 \) to prover.
- **Round 3**:
  - Prover computes:
    \[
    s = k - c \cdot x = 7 - 4 \cdot 5 = -13
    \]
  - Sends \( s \) to verifier.
- **Final Check**:
  - Verifier checks:
    \[
    R_1 = g^s \cdot Y_1^c = 2^{-13} \cdot 32^4, \quad R_2 = h^s \cdot Y_2^c = 3^{-13} \cdot 243^4
    \]
  - If valid, the proof is accepted.

---
