import { run } from "./db.js";

async function main() {
  await run("DELETE FROM users", []);
  await run(
    "INSERT INTO users (name, role, password) VALUES (?, 'admin', ?)",
    ["alice", "alice_pw"]
  );
  await run(
    "INSERT INTO users (name, role, password) VALUES (?, 'user', ?)",
    ["bob", "bob_pw"]
  );
  await run(
    "INSERT INTO users (name, role, password) VALUES (?, 'user', ?)",
    ["carol", "carol_pw"]
  );
  console.log("Seeded users: alice(admin), bob(user), carol(user)");
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
