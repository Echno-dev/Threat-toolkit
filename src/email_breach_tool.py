"""
Menu-driven CLI wrapper for email breach functions.
"""

from modules import email_breach

def menu():
    last_report = None
    while True:
        print("\n=== Email Breach Tool ===")
        print("1) Check email (Local DB)")
        print("2) Check email (LeakCheck API)")
        print("3) Check password (HIBP Pwned Passwords)")
        print("4) Export last report")
        print("0) Exit")
        choice = input("Choose: ").strip()

        if choice == "0":
            break
        elif choice in ("1", "2"):
            email = input("Enter email: ").strip()
            provider = "local" if choice == "1" else "leakcheck"
            rpt, breaches, err = email_breach.run_email_breach(email, provider=provider, force_refresh=True)
            print(rpt)
            last_report = rpt
        elif choice == "3":
            pwd = input("Enter password: ").strip()
            found, count, err = email_breach.check_pwned_password(pwd)
            if err:
                print("Error:", err)
            elif found:
                print(f"Password found in {count} breaches.")
            else:
                print("Password not found in breaches.")
        elif choice == "4":
            if not last_report:
                print("No report to export.")
                continue
            path = input("Save path: ").strip() or "breach_report.txt"
            ok = email_breach.export_report(last_report, path)
            print("Exported:", ok, "to", path)

if __name__ == "__main__":
    menu()
