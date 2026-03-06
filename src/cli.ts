#!/usr/bin/env bun
import { initDB, listUsers, deleteById } from "./store";

const command = process.argv[2];

if (!process.env.PROXY_SECRET || process.env.PROXY_SECRET.length < 32) {
  console.error("PROXY_SECRET must be set and at least 32 characters");
  process.exit(1);
}

initDB();

async function list() {
  const users = await listUsers();
  if (users.length === 0) {
    console.log("No users found.");
    return;
  }
  console.log(`\n  ID  | Email                          | Created`);
  console.log(`------+--------------------------------+---------------------`);
  for (const u of users) {
    const id = String(u.id).padStart(4);
    const email = u.rohlikEmail.padEnd(30);
    console.log(`  ${id} | ${email} | ${u.createdAt}`);
  }
  console.log(`\n  Total: ${users.length} user(s)\n`);
}

async function remove(idArg: string) {
  const id = parseInt(idArg, 10);
  if (isNaN(id)) {
    console.error("Invalid ID. Usage: bun run cli delete <id>");
    process.exit(1);
  }
  const deleted = deleteById(id);
  if (deleted) {
    console.log(`User ${id} deleted.`);
  } else {
    console.error(`User ${id} not found.`);
    process.exit(1);
  }
}

function usage() {
  console.log(`
Rohlik MCP Proxy - Account Management CLI

Usage:
  bun run cli list              List all registered users
  bun run cli delete <id>       Delete a user by ID

Requires PROXY_SECRET environment variable (same as the server).
`);
}

switch (command) {
  case "list":
    await list();
    break;
  case "delete":
    await remove(process.argv[3]);
    break;
  default:
    usage();
    break;
}
