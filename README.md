# xui-management

Restricted users inside the 3x-ui dashboard. An admin gets a **Management** item directly under **Xray Configs**, creates a user, and chooses the inbounds and ports that user can see. The user signs in on the same panel URL. They can work with those inbounds only. Each user can also have a Telegram bot that reports that inbound and CPU, and nothing else.

3x-ui compiles its sidebar into each release, and the menu has already changed between versions. This add-on does not fork one release. It serves the panel you already installed, inserts the menu item in the live page, and checks every request again on the server. Admin traffic is passed through unchanged.

## Install on the VPS

Run this on the same machine as 3x-ui, as root:

```bash
bash install.sh
```

The installer reads the panel port and web path from `x-ui.db`, asks for the admin password, moves 3x-ui to `127.0.0.1` on an internal port, and listens on the original public port. The address you already use stays the same. `uninstall.sh` puts the port back.

Turn off 3x-ui two-factor login for the admin account. The add-on has to keep its own admin session, and a rotating code cannot be stored in the config. Restricted users do not get that password.

Open the panel, then **Xray Configs**, then **Management**.

## What a restricted user can do

They use the normal inbounds and clients screens. The server drops every other inbound from the lists, blocks settings, Xray config, nodes, hosts, and backups, and rejects a client change when the inbound is not theirs. Delete, edit, reset, and add can be turned off per user. A client cap applies to the whole inbound.

A port in **Also allow these ports** keeps matching. If you later create another inbound on that port, this user gets it too.

They can add, edit, reset, and delete any client on an inbound you assigned, including clients you created there.

## Telegram

For each user, create a bot with BotFather and set the bot token plus the numeric chat id (send `/start` to the bot, then read the id from @userinfobot or `getUpdates`). The bot sends:

- a periodic summary of that user's inbounds (traffic, client counts, online count)
- CPU on that same message
- a separate CPU alert when usage stays at or above the threshold (at most once every 10 minutes)

It does not send other inbounds, panel logins, Xray config, or disk and memory. `/status` in that chat replies with the same summary. Messages from any other chat are ignored.

The first scheduled report waits one full interval after the service starts.

## Manual setup

If you would rather not move the panel port, copy `config.example.json` to `config.json`, point `panel_url` at 3x-ui, and run:

```bash
python3 -m xui_management -c config.json
```

People must open this process, not 3x-ui directly, or a restricted user can bypass it. `python3 -m xui_management -c config.json check` checks the admin login and prints inbounds.

## Logs and removal

```bash
journalctl -u xui-management -f
bash uninstall.sh
```

`uninstall.sh` restores the original listen address and stops the add-on. The files in `/opt/xui-management` stay in place.
