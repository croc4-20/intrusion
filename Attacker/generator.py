import random
import urllib.parse

def change_case(payload):
    # Randomly flip case for each character
    return ''.join(c.upper() if random.random() > 0.5 else c.lower() for c in payload)

def insert_comments(payload):
    # Insert a harmless SQL comment into the payload at random positions
    words = payload.split()
    if len(words) < 2:
        return payload
    insert_index = random.randint(1, len(words)-1)
    words.insert(insert_index, "--")
    return ' '.join(words)

def url_encode(payload):
    # URL-encode parts of the payload
    return urllib.parse.quote(payload)

def mutate_payload(payload, mutation_level=1):
    """Generate a mutated payload based on a mutation level parameter."""
    mutated = payload
    if mutation_level >= 1:
        mutated = change_case(mutated)
    if mutation_level >= 2:
        mutated = insert_comments(mutated)
    if mutation_level >= 3:
        mutated = url_encode(mutated)
    return mutated

if __name__ == "__main__":
    base_payload = "SELECT * FROM users WHERE username = 'admin'"
    print("Base Payload:", base_payload)
    for level in range(1, 4):
        mutated = mutate_payload(base_payload, mutation_level=level)
        print(f"Mutated Payload (Level {level}):", mutated)
