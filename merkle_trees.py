from pymerkle import *
import sys
from hashlib import sha256

# Convert a Python string to its SHA256 hash hexstring
def str_to_sha256_hex(s):
    encoded=s.encode()
    return sha256(encoded).hexdigest()


#######################
# Demo Part (1):
# Create a Merkle Tree
#######################
def part1():
    print("\n")

    blockchain_buddies = [
        'Mark',
        'Harun',
        'Aagat',
        'Jonathan'
    ]
    # Display hashes
    for buddy in blockchain_buddies:
        print(f'The SHA-256 hash for {buddy} is: {str_to_sha256_hex(buddy)}')
    print("\n")

    # Add (encrypt) names into Merkle tree and display
    tree = MerkleTree(hash_type='sha256', encoding='utf-8', raw_bytes=True, security=False)
    for buddy in blockchain_buddies:
        print(f'Adding {buddy} to tree...')
        tree.encryptRecord(buddy)

    print("\nMerkle Tree:", tree)
    return tree


#######################
# Demo Part (2):
# Merkle Proofs
#######################
'''
Commitment is the Merkle-tree’s acclaimed root-hash at the exact moment of 
proof generation (that is, before any other records are possibly encrypted 
into the tree). The Merkle-proof is valid iff the advertized path of 
hashes leads to the inscribed commitment.

Generating the correct audit proof based upon a provided checksum proves 
on behalf of the server that the data, whose digest coincides with this 
checksum, has indeed been encrypted into the Merkle-tree. The client 
(auditor) verifies correctness of proof (and consequently inclusion of 
their data among the tree’s encrypted records) by validating it against 
the Merkle-tree’s current root-hash. It is essential that the auditor 
does not need to reveal the data itself but only their checksum, whereas 
the server publishes the least possible encrypted data (at most two 
checksums stored by leaves) along with advertising the current root-hash.
https://pymerkle.readthedocs.io/en/latest/decoupling.html 
'''

def part2():
    # Test names that are and are not in the tree.
    # (Imagine the server is a Bitcoin full node -- with all transactions -- 
    # and the client is a lightweight node that only has the root hash of the 
    # Merkle tree containing all transactions for a particular block).
    tree = part1()
    challenge_strings = ['Mark', 'Voldemort']
    for challenge_str in challenge_strings:
        print(f"Generating proof that {challenge_str} is in the Merkle tree...")
        # Pretend the client generates the checksum and sends the server
        checksum = str_to_sha256_hex(challenge_str)
        # Server receives the checksum, creates a proof, and sends it to client
        proof = tree.auditProof(checksum)
        print(proof)
        # Client has the root hash (AKA the commitment)
        commitment = tree.get_commitment()
        # Client verifies the proof using the root hash
        print(f"Validating proof that {challenge_str} is in the Merkle tree with root hash: {commitment}")
        result = validateProof(proof, commitment)
        print(f"The proof for {challenge_str} is {result}\n")

if "part1" in sys.argv:
    part1()

if "part2" in sys.argv:
    part2()