def confirm_action(description: str, command: str = None, impact: str = None) -> bool:
    print("\n" + "="*50)
    print("ACTION REQUIRES CONFIRMATION")
    print(description)
    if command:
        print(f"Command: {command}")
    if impact:
        print(f"Potential impact: {impact}")
    print("="*50)
    while True:
        response = input("Proceed? (yes/no): ").strip().lower()
        if response in ["yes", "no"]:
            return response == "yes"
        print("Please answer 'yes' or 'no'.")