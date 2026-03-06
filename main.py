import argparse
from orchestrator import Orchestrator

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Autonomous Pentesting Agent")
    parser.add_argument("target", nargs="?", default="127.0.0.1", help="Target IP or hostname")
    parser.add_argument("--scope", default="", help="Scope (CIDR range)")
    parser.add_argument("--data-dir", default="./data", help="Data directory")
    parser.add_argument("--max-steps", type=int, default=25, help="Maximum autonomous steps")
    parser.add_argument("--policy-path", default="policy.json", help="Path to policy file")
    parser.add_argument(
        "--no-confirmation",
        action="store_true",
        help="Disable interactive confirmations (useful for automation)",
    )
    args = parser.parse_args()

    agent = Orchestrator(
        args.target,
        args.scope,
        args.data_dir,
        args.max_steps,
        require_user_confirmation=not args.no_confirmation,
        policy_path=args.policy_path,
    )
    agent.run()
