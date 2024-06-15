import os

# Function to generate a random pepper
def generate_pepper():
    return os.urandom(32).hex()  # Generate a 32-byte (256-bit) random pepper and convert to hexadecimal string

# Save the pepper to a file
def save_pepper(pepper):
    with open('pepper.txt', 'w') as file:
        file.write(pepper)

# Example usage
if __name__ == "__main__":
    # Generate a random pepper
    pepper = generate_pepper()

    # Save the pepper to a file
    save_pepper(pepper)

    print("Pepper:", pepper)
    print("Pepper saved to pepper.txt")
