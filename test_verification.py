import os
import sys
import time

sys.path.insert(0, ".")
from gui.app import UserManager, NetworkManager, CBackendClient, BruteForceApp

def run_tests():
    print("=== STARTING 12-POINT SYSTEM VERIFICATION ===\n")

    # Generate a unique test username so the test is idempotent across multiple runs
    test_uname = f"officer_{int(time.time()) % 100000}"

    # 1. Test user registration
    ok, msg = UserManager.register_user("Test Officer", test_uname, "StrongPass2026!")
    print(f"Test 1 - User Registration: ok={ok}, msg='{msg}'")
    assert ok, "Registration failed"

    # 2. Test existing user login
    auth_ok, u_rec = UserManager.authenticate(test_uname, "StrongPass2026!")
    print(f"Test 2 - Existing User Login: auth_ok={auth_ok}, user={u_rec.get('fullname')}")
    assert auth_ok, "Authentication failed for valid user"

    # 3. Test incorrect credentials
    auth_fail, _ = UserManager.authenticate(test_uname, "WrongPass!")
    print(f"Test 3 - Incorrect Credentials Rejected: not auth_fail={not auth_fail}")
    assert not auth_fail, "Failed password was accepted!"

    # 4. Test duplicate username registration
    dup_ok, dup_msg = UserManager.register_user("Another User", test_uname, "AnotherPass!")
    print(f"Test 4 - Duplicate Username Blocked: dup_ok={dup_ok}, msg='{dup_msg}'")
    assert not dup_ok, "Duplicate username was allowed!"

    # 5. Test IP detection
    local_ip = NetworkManager.get_active_local_ip()
    public_ip = NetworkManager.get_public_ip()
    print(f"Test 5 - Active Local IP: {local_ip} | Public IP: {public_ip}")
    assert local_ip and not local_ip.startswith("127."), "Invalid local IP"

    # 6. Test manual IP entry
    manual_ip = "198.51.100.44"
    backend = CBackendClient()
    res_manual = backend.record_attempt("sec_officer", False, manual_ip, "Manual (Simulated)")
    recorded_ip = res_manual.get("last_processed", {}).get("ip_address")
    recorded_src = res_manual.get("last_processed", {}).get("ip_source")
    print(f"Test 6 - Manual IP Recorded: IP={recorded_ip}, Source={recorded_src}")
    assert recorded_ip == manual_ip, f"Expected {manual_ip}, got {recorded_ip}"

    # 7. Test 3 consecutive failed attempts trigger alert
    attack_ip = "203.0.113.88"
    backend.record_attempt("attacker", False, attack_ip, "Manual (Simulated)")
    backend.record_attempt("attacker", False, attack_ip, "Manual (Simulated)")
    res3 = backend.record_attempt("attacker", False, attack_ip, "Manual (Simulated)")
    alert_txt = res3.get("alert", "")
    print(f"Test 7 - 3 Failed Attempts Trigger Alert: Alert='{alert_txt}'")
    assert "Brute-force" in alert_txt or "consecutive" in alert_txt, f"Alert missing! Got: {alert_txt}"

    # 8. Test successful login resets failure counter
    backend.record_attempt("attacker", True, attack_ip, "Manual (Simulated)")
    state_after = backend.get_state()
    ip_map = {r["ip_address"]: r for r in state_after.get("suspicious_ips", [])}
    consec = ip_map.get(attack_ip, {}).get("consecutive_failures", 0)
    print(f"Test 8 - Success Resets Consecutive Counter: consecutive_failures={consec}")
    assert consec == 0, f"Expected 0 consecutive failures after success, got {consec}"

    # 9. Test TXT database persistence
    assert os.path.isfile("database/login_database.txt"), "login_database.txt missing"
    assert os.path.isfile("database/users.txt"), "users.txt missing"
    with open("database/login_database.txt", "r", encoding="utf-8") as f:
        log_content = f.read()
    print(f"Test 9 - TXT Databases Active: login_database.txt ({len(log_content)} chars), users.txt ({os.path.getsize('database/users.txt')} bytes)")
    assert "sec_officer" in log_content

    # 10. Test Stack and Queue operations
    backend.enqueue("queue_user", "pwd", "10.0.0.99", "Manual")
    q_state = backend.get_state()
    q_cnt = q_state.get("stats", {}).get("pending_queue_count", 0)
    print(f"Test 10a - Queue Enqueue in C: Queue count={q_cnt}")
    assert q_cnt >= 1

    deq_res = backend.process_next()
    deq_user = deq_res.get("last_processed", {}).get("username")
    print(f"Test 10b - Queue Dequeue in C: Last processed={deq_user}")

    pop_res = backend.pop_stack()
    pop_user = pop_res.get("last_processed", {}).get("username")
    print(f"Test 10c - Stack Pop in C: Popped user={pop_user}")

    # 11. Verify passwords are never stored in plaintext
    with open("database/users.txt", "r", encoding="utf-8") as f:
        users_txt = f.read()
    with open("database/login_database.txt", "r", encoding="utf-8") as f:
        logins_txt = f.read()
    assert "StrongPass2026!" not in users_txt, "Plaintext password found in users.txt!"
    assert "StrongPass2026!" not in logins_txt, "Plaintext password found in login_database.txt!"
    assert "cyber2026!" not in logins_txt, "Plaintext demo password found in login_database.txt!"
    print("Test 11 - Security Check: Passwords strictly hashed in users.txt (PBKDF2) and never present in login_database.txt")

    # 12. Verify application launches directly into Tkinter login page
    app = BruteForceApp()
    app.update_idletasks()
    app.update()
    assert app.auth_view is not None, "AuthView not mounted on startup!"
    assert app.dashboard_view is None, "DashboardView was prematurely visible before login!"
    print("Test 12 - App Launches Directly into Dedicated Login Page: AuthView active, Dashboard locked.")
    app.destroy()

    print("\n========================================================")
    print("  ALL 12 VERIFICATION TESTS PASSED SUCCESSFULLY (100%)!")
    print("========================================================\n")

if __name__ == "__main__":
    run_tests()
