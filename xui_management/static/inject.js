(function () {
  var script = document.currentScript;
  if (!script) return;
  var mgmtBase = new URL(script.src, location.href).pathname.replace(/inject\.js$/, "");
  var panelBase = mgmtBase.replace(/__xmgmt\/$/, "");
  if (/(?:^|; )xmgmt_role=user(?:;|$)/.test(document.cookie)) {
    var portMatch = document.cookie.match(/(?:^|; )xmgmt_port=(\d+)/);
    var here = String(location.port || (location.protocol === "https:" ? "443" : "80"));
    if (portMatch && here !== portMatch[1]) {
      location.replace(location.protocol + "//" + location.hostname + ":" + portMatch[1] + "/");
      return;
    }
    if (!portMatch && location.pathname.indexOf("__xmgmt/client") === -1) {
      location.replace(mgmtBase + "client");
      return;
    }
  }
  var role = "";
  var frame = null;
  var applying = false;

  var css = document.createElement("style");
  css.textContent = [
    "#xmgmt-frame{position:fixed;z-index:30;border:0;background:#0b1220;display:none}",
    "body.xmgmt-open .ant-menu-item-selected:not([data-xmgmt]),body.xmgmt-open .router-link-active{background:transparent!important;color:inherit!important}",
    "body.xmgmt-open [data-xmgmt].ant-menu-item,body.xmgmt-open [data-xmgmt].ant-menu-item > a{color:#fff!important}"
  ].join("");
  document.head.appendChild(css);

  function api(path) {
    return fetch(panelBase + "__xmgmt/api/" + path, { credentials: "same-origin" }).then(function (res) {
      return res.json().then(function (body) { return { ok: res.ok, body: body }; });
    });
  }

  function isXrayRoot(el) {
    var id = el.getAttribute("data-menu-id") || "";
    var href = (el.getAttribute("href") || "").split("?")[0];
    if (/\/xray$/.test(id)) return true;
    if (/\/xray\/?$/.test(href)) return true;
    return false;
  }

  function itemOf(el) {
    if (el.closest) {
      var li = el.closest("li.ant-menu-item, li.ant-menu-submenu, li");
      if (li) return li;
    }
    return el;
  }

  function xrayItems() {
    var found = [];
    var nodes = document.querySelectorAll("a[href], [data-menu-id]");
    var i;
    for (i = 0; i < nodes.length; i++) {
      if (!isXrayRoot(nodes[i])) continue;
      var li = itemOf(nodes[i]);
      if (found.indexOf(li) === -1) found.push(li);
    }
    if (found.length) return found;
    var items = document.querySelectorAll("ul.ant-menu > li");
    for (i = 0; i < items.length; i++) {
      var title = items[i].querySelector(".ant-menu-submenu-title, .ant-menu-title-content, a span, span");
      var text = (title ? title.textContent : items[i].textContent || "").replace(/\s+/g, " ").trim().toLowerCase();
      if (text === "xray configs" || text === "xray") found.push(items[i]);
    }
    return found;
  }

  function setLabel(root, text) {
    var spans = root.querySelectorAll("span");
    var target = null;
    for (var i = 0; i < spans.length; i++) {
      if (spans[i].closest && spans[i].closest(".anticon, svg")) continue;
      if ((spans[i].textContent || "").trim()) target = spans[i];
    }
    if (target) target.textContent = text;
  }

  function paintIcon(svg) {
    svg.setAttribute("viewBox", "0 0 1024 1024");
    svg.setAttribute("fill", "currentColor");
    svg.setAttribute("aria-hidden", "true");
    svg.innerHTML = '<path d="M824.2 699.9a301.55 301.55 0 00-86.4-60.4C783.1 602.8 812 546.8 812 484c0-110.3-89.7-200-200-200s-200 89.7-200 200c0 62.8 28.9 118.8 74.2 155.5a300.95 300.95 0 00-86.4 60.4C346.1 757.8 320 826.8 320 896.8c0 4.4 3.6 8 8 8h56c4.4 0 8-3.6 8-8 0-104.6 85.2-189.8 189.8-189.8 104.7 0 189.9 85.2 189.9 189.8 0 4.4 3.6 8 8 8H824c4.4 0 8-3.6 8-8 .1-70-26-139-73.8-196.9zM512 596c-62 0-112.4-50.4-112.4-112.4S450 371.2 512 371.2s112.4 50.4 112.4 112.4S574 596 512 596z"></path>';
  }

  function existingItem(parent) {
    if (!parent) return null;
    var kids = parent.children;
    for (var i = 0; i < kids.length; i++) {
      if (kids[i].getAttribute && kids[i].getAttribute("data-xmgmt") === "1") return kids[i];
    }
    return null;
  }

  function placeItem(anchor) {
    var parent = anchor.parentElement;
    if (!parent) return;
    var current = existingItem(parent);
    if (current) {
      if (current.previousElementSibling !== anchor) parent.insertBefore(current, anchor.nextSibling);
      return;
    }
    var sample = anchor.classList.contains("ant-menu-item") ? anchor : parent.querySelector("li.ant-menu-item") || anchor;
    var li = sample.cloneNode(true);
    li.setAttribute("data-xmgmt", "1");
    li.removeAttribute("id");
    li.classList.remove("ant-menu-item-selected");
    var links = li.querySelectorAll("a");
    for (var i = 0; i < links.length; i++) {
      links[i].setAttribute("href", "javascript:void(0)");
      links[i].classList.remove("router-link-active", "router-link-exact-active");
    }
    setLabel(li, "Management");
    var svg = li.querySelector("svg");
    if (svg) paintIcon(svg);
    li.addEventListener("click", function (event) {
      event.preventDefault();
      event.stopPropagation();
      openFrame();
    });
    parent.insertBefore(li, anchor.nextSibling);
  }

  function apply() {
    if (applying) return;
    applying = true;
    try {
      if (role === "admin") {
        var items = xrayItems();
        for (var i = 0; i < items.length; i++) placeItem(items[i]);
      }
      hideRestricted();
      if (frame && frame.style.display !== "none") {
        placeFrame();
        markSelected();
      }
    } finally {
      applying = false;
    }
  }

  function hideRestricted() {
    if (role !== "user") return;
    var nodes = document.querySelectorAll("[data-menu-id], a[href]");
    var deny = /\/(settings|setting|xray|nodes|hosts|outbound|routing|api-docs|groups)(\/|$|\?|#)/i;
    for (var i = 0; i < nodes.length; i++) {
      var blob = (nodes[i].getAttribute("data-menu-id") || "") + " " + (nodes[i].getAttribute("href") || "");
      if (!deny.test(blob)) continue;
      var li = itemOf(nodes[i]);
      if (li && li.getAttribute("data-xmgmt") !== "1") li.style.display = "none";
    }
    if (deny.test(location.pathname + location.hash)) location.replace(inboundUrl());
  }

  function inboundUrl() {
    var nodes = document.querySelectorAll("a[href], [data-menu-id]");
    for (var i = 0; i < nodes.length; i++) {
      var href = (nodes[i].getAttribute("href") || "").split("?")[0];
      if (/\/inbounds\/?$/.test(href)) return href;
      var id = nodes[i].getAttribute("data-menu-id") || "";
      var marker = id.lastIndexOf("-/");
      if (marker !== -1 && /\/inbounds$/.test(id.slice(marker + 1))) {
        return panelBase.replace(/\/$/, "") + id.slice(marker + 1);
      }
    }
    return panelBase + "panel/inbounds";
  }

  function theme() {
    var name = (document.documentElement.className + " " + document.body.className).toLowerCase();
    if (name.indexOf("dark") !== -1 || name.indexOf("ultra") !== -1) return "dark";
    var bg = getComputedStyle(document.body).backgroundColor || "";
    var bits = bg.match(/\d+/g);
    if (bits && bits.length >= 3) {
      var lum = (parseInt(bits[0], 10) + parseInt(bits[1], 10) + parseInt(bits[2], 10)) / 3;
      if (lum < 140) return "dark";
    }
    return "light";
  }

  function sidebarBox() {
    var sider = document.querySelector("#sider, .ant-layout-sider");
    if (!sider) return null;
    var rect = sider.getBoundingClientRect();
    if (rect.width < 48 || rect.width > 480 || rect.left > 40) return null;
    return rect;
  }

  function placeFrame() {
    var box = sidebarBox();
    var left = box ? Math.round(box.right) : 0;
    var top = 0;
    frame.style.top = top + "px";
    frame.style.left = left + "px";
    frame.style.width = Math.max(320, window.innerWidth - left) + "px";
    frame.style.height = Math.max(320, window.innerHeight - top) + "px";
  }

  function markSelected() {
    document.body.classList.add("xmgmt-open");
    var selected = document.querySelectorAll(".ant-menu-item-selected, a.router-link-active, a.router-link-exact-active");
    for (var i = 0; i < selected.length; i++) {
      var owner = selected[i].closest ? selected[i].closest("[data-xmgmt]") : null;
      if (owner) continue;
      selected[i].classList.remove("ant-menu-item-selected", "router-link-active", "router-link-exact-active");
    }
    var ours = document.querySelectorAll("[data-xmgmt]");
    for (var j = 0; j < ours.length; j++) {
      ours[j].classList.add("ant-menu-item-selected");
      var link = ours[j].querySelector("a");
      if (link) link.classList.add("router-link-active");
    }
  }

  function openFrame() {
    if (!frame) {
      frame = document.createElement("iframe");
      frame.id = "xmgmt-frame";
      frame.title = "Management";
      frame.src = mgmtBase + "ui?theme=" + theme();
      document.body.appendChild(frame);
    }
    frame.style.display = "block";
    placeFrame();
    markSelected();
  }

  function closeFrame() {
    if (!frame) return;
    frame.style.display = "none";
    document.body.classList.remove("xmgmt-open");
    var ours = document.querySelectorAll("[data-xmgmt]");
    for (var i = 0; i < ours.length; i++) {
      ours[i].classList.remove("ant-menu-item-selected");
      var link = ours[i].querySelector("a");
      if (link) link.classList.remove("router-link-active", "router-link-exact-active");
    }
  }

  document.addEventListener("click", function (event) {
    if (!frame || frame.style.display === "none") return;
    if (event.target.closest && event.target.closest("[data-xmgmt]")) return;
    if (event.target.closest && event.target.closest(".ant-menu-item, .ant-menu-submenu-title, a[href]")) closeFrame();
  }, true);
  window.addEventListener("resize", function () {
    if (frame && frame.style.display !== "none") placeFrame();
  });

  api("me").then(function (res) {
    if (!res.ok || !res.body || !res.body.obj) return;
    role = res.body.obj.role || "";
    apply();
    var obs = new MutationObserver(function () { apply(); });
    obs.observe(document.documentElement, { childList: true, subtree: true });
  }).catch(function () {});
})();
