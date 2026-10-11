(function () {
  var params = new URLSearchParams(location.search);
  document.documentElement.setAttribute("data-theme", params.get("theme") === "light" ? "light" : "dark");

  var users = [];
  var inbounds = [];
  var inboundWarning = "";
  var selected = null;

  function toast(text) {
    var el = document.getElementById("toast");
    el.hidden = false;
    el.textContent = text;
    clearTimeout(toast._t);
    toast._t = setTimeout(function () { el.hidden = true; }, 2400);
  }

  function api(path, body) {
    var opts = { credentials: "same-origin", headers: { "X-XMGMT": "1" } };
    if (body !== undefined) {
      opts.method = "POST";
      opts.headers["Content-Type"] = "application/json";
      opts.body = JSON.stringify(body);
    }
    return fetch("../__xmgmt/api/" + path, opts).then(function (res) {
      return res.json().catch(function () { return { success: false, msg: "Bad response" }; }).then(function (data) {
        if (!res.ok || data.success === false) throw new Error(data.msg || "Request failed");
        return data;
      });
    });
  }

  function showWarning(text, username) {
    var box = document.getElementById("warn");
    if (!text) { box.hidden = true; return; }
    box.hidden = false;
    document.getElementById("warn-text").textContent = text;
    if (username) document.getElementById("panel-user").value = username;
  }

  function blank() {
    return {
      username: "",
      password: "",
      inbound_ids: [],
      inbound_ports: [],
      max_clients: 0,
      permissions: { add: true, edit: true, delete: false, reset: true },
      telegram: { enabled: false, bot_token: "", chat_id: "", report_minutes: 60, cpu_threshold: 80 }
    };
  }

  function renderUsers() {
    var root = document.getElementById("users");
    var html = '<button type="button" class="add" id="new">+ New user</button>';
    if (!users.length) html += '<div class="empty">No restricted users yet.</div>';
    users.forEach(function (user, index) {
      var bits = [];
      if (user.inbound_ids.length) bits.push(user.inbound_ids.length + " inbound" + (user.inbound_ids.length === 1 ? "" : "s"));
      if (user.inbound_ports.length) bits.push("ports " + user.inbound_ports.join(", "));
      if (user.telegram && user.telegram.enabled) bits.push("bot on");
      html += '<button type="button" class="row' + (selected === index ? " on" : "") + '" data-i="' + index + '"><strong>' +
        escapeHtml(user.username) + '</strong><span>' + escapeHtml(bits.join(" · ") || "No access set") + "</span></button>";
    });
    root.innerHTML = html;
    document.getElementById("new").onclick = function () { selected = -1; renderUsers(); renderEditor(blank()); };
    Array.prototype.forEach.call(root.querySelectorAll("[data-i]"), function (button) {
      button.onclick = function () {
        selected = Number(button.getAttribute("data-i"));
        renderUsers();
        renderEditor(Object.assign(blank(), JSON.parse(JSON.stringify(users[selected])), { password: "" }));
      };
    });
  }

  function renderEditor(user) {
    var form = document.getElementById("editor");
    var boxes = inbounds.map(function (inbound) {
      var checked = user.inbound_ids.indexOf(Number(inbound.id)) !== -1 ? " checked" : "";
      return '<label><input type="checkbox" name="ib" value="' + inbound.id + '"' + checked + '><span>' +
        escapeHtml(inbound.remark || ("Inbound " + inbound.id)) +
        "<small>" + escapeHtml(inbound.protocol || "") + " · port " + inbound.port + " · id " + inbound.id + "</small></span></label>";
    }).join("");
    form.innerHTML =
      '<div class="grid">' +
      field("Username", "username", user.username, "text") +
      field("Password", "password", "", "password", user.username ? "Leave blank to keep the current password" : "At least 8 characters") +
      '<div class="field wide"><label>Inbounds</label><div class="inbounds">' + (boxes || '<div class="empty">' + escapeHtml(inboundWarning || "No inbounds returned by the panel.") + "</div>") + "</div></div>" +
      field("Also allow these ports", "ports", user.inbound_ports.join(", "), "text", "Comma separated. A new inbound on one of these ports is included automatically.") +
      field("Max clients", "max_clients", user.max_clients ? String(user.max_clients) : "", "number", "0 or empty means no cap. Counts every client on the inbound.") +
      "</div>" +
      '<div class="field"><label>Permissions</label><div class="perms checks">' +
      perm("add", "Add clients", user) + perm("edit", "Edit", user) + perm("reset", "Reset traffic", user) + perm("delete", "Delete", user) +
      "</div></div>" +
      '<div class="section"><h2>Telegram bot</h2>' +
      '<p class="hint">The bot reports only this user\'s inbounds, plus CPU. It does not send other inbounds, logins, or panel settings. Create the bot with @BotFather and put your numeric chat id here.</p>' +
      '<div class="switch"><span>Send reports</span><label class="checks"><input type="checkbox" id="tg_on"' + (user.telegram.enabled ? " checked" : "") + "> Enabled</label></div>" +
      '<div class="grid">' +
      field("Bot token", "bot_token", user.telegram.bot_token, "text") +
      field("Chat id", "chat_id", user.telegram.chat_id, "text") +
      field("Report every (minutes)", "report_minutes", String(user.telegram.report_minutes || 60), "number", "From 5 to 1440. The first report waits one full interval.") +
      field("CPU alert above (%)", "cpu_threshold", String(user.telegram.cpu_threshold || 0), "number", "0 turns the extra alert off. CPU is still included in the regular report.") +
      "</div></div>" +
      '<div class="row-actions"><button class="btn" type="submit">Save user</button>' +
      '<button class="btn ghost" type="button" id="test">Test bot</button>' +
      (user.username ? '<button class="btn danger" type="button" id="del">Delete</button>' : "") +
      "</div>";
    form.onsubmit = function (event) {
      event.preventDefault();
      save(user.username);
    };
    var test = document.getElementById("test");
    if (test) test.onclick = function () { testBot(); };
    var del = document.getElementById("del");
    if (del) del.onclick = function () { remove(user.username); };
  }

  function field(label, name, value, type, hint) {
    return '<div class="field' + (name === "ports" || name === "bot_token" ? " wide" : "") + '"><label>' + label + "</label>" +
      '<input id="' + name + '" name="' + name + '" type="' + type + '" value="' + escapeAttr(value) + '"' +
      (type === "number" ? ' min="0"' : "") + ">" +
      (hint ? '<div class="hint">' + hint + "</div>" : "") + "</div>";
  }

  function perm(key, label, user) {
    return '<label><input type="checkbox" name="perm" value="' + key + '"' + (user.permissions[key] ? " checked" : "") + "> " + label + "</label>";
  }

  function value(id) {
    var el = document.getElementById(id);
    return el ? el.value.trim() : "";
  }

  function collect(originalName) {
    var ids = [];
    Array.prototype.forEach.call(document.querySelectorAll('input[name="ib"]:checked'), function (box) {
      ids.push(Number(box.value));
    });
    var ports = value("ports").split(",").map(function (part) { return part.trim(); }).filter(Boolean).map(Number);
    var perms = { add: false, edit: false, delete: false, reset: false };
    Array.prototype.forEach.call(document.querySelectorAll('input[name="perm"]:checked'), function (box) {
      perms[box.value] = true;
    });
    return {
      username: value("username") || originalName,
      password: value("password"),
      inbound_ids: ids,
      inbound_ports: ports,
      max_clients: Number(value("max_clients") || 0),
      permissions: perms,
      telegram: {
        enabled: document.getElementById("tg_on").checked,
        bot_token: value("bot_token"),
        chat_id: value("chat_id"),
        report_minutes: Number(value("report_minutes") || 60),
        cpu_threshold: Number(value("cpu_threshold") || 0)
      }
    };
  }

  function save(originalName) {
    var body = collect(originalName);
    api("users/save", body).then(function () {
      toast("Saved");
      return refresh(body.username);
    }).catch(function (err) { toast(err.message); });
  }

  function remove(username) {
    if (!username || !confirm("Delete " + username + "?")) return;
    api("users/delete", { username: username }).then(function () {
      toast("Deleted");
      selected = null;
      return refresh();
    }).catch(function (err) { toast(err.message); });
  }

  function testBot() {
    api("telegram/test", { bot_token: value("bot_token"), chat_id: value("chat_id") })
      .then(function () { toast("Test message sent"); })
      .catch(function (err) { toast(err.message); });
  }

  function refresh(selectName) {
    return api("users").then(function (data) {
      users = data.obj || [];
      if (selectName) {
        selected = users.findIndex(function (user) { return user.username === selectName; });
      }
      renderUsers();
      if (selected === null || selected < 0 || !users[selected]) renderEditor(blank());
      else renderEditor(Object.assign(blank(), JSON.parse(JSON.stringify(users[selected])), { password: "" }));
    });
  }

  function escapeHtml(text) {
    return String(text == null ? "" : text).replace(/[&<>"']/g, function (ch) {
      return ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[ch];
    });
  }
  function escapeAttr(text) { return escapeHtml(text); }

  function loadAll() {
    return Promise.all([
      api("inbounds").catch(function (err) {
        return { obj: [], warning: err.message, panel_username: "" };
      }),
      api("users")
    ]).then(function (result) {
      inbounds = result[0].obj || [];
      inboundWarning = result[0].warning || "";
      showWarning(inboundWarning, result[0].panel_username || "");
      showClientUrl(result[0].client_port || "");
      if (result[0].client_port) document.getElementById("client-port").value = result[0].client_port;
      users = result[1].obj || [];
      renderUsers();
      renderEditor(blank());
    });
  }

  function showClientUrl(port) {
    var el = document.getElementById("client-url");
    if (!port) {
      el.textContent = "Not set. Pick a free port, for example 8788. Then open that port in the firewall.";
      return;
    }
    el.textContent = "Users open " + location.protocol + "//" + location.hostname + ":" + port + "/";
  }

  document.getElementById("client-port-save").onclick = function () {
    api("client-port", { port: Number(document.getElementById("client-port").value) }).then(function (data) {
      toast("User panel port saved");
      showClientUrl(data.obj && data.obj.port);
    }).catch(function (err) { toast(err.message); });
  };

  document.getElementById("panel-save").onclick = function () {
    api("panel-login", {
      username: document.getElementById("panel-user").value.trim(),
      password: document.getElementById("panel-pass").value
    }).then(function () {
      toast("Panel login saved");
      document.getElementById("panel-pass").value = "";
      return loadAll();
    }).catch(function (err) { toast(err.message); });
  };

  loadAll().catch(function (err) {
    document.getElementById("users").innerHTML = '<div class="empty">' + escapeHtml(err.message) + "</div>";
    document.getElementById("editor").innerHTML = '<div class="empty">Sign in to 3x-ui as the admin, then open Management again.</div>';
  });
})();
