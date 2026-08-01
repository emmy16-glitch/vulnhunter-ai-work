(() => {
  "use strict";

  if (typeof document === "undefined" || typeof window === "undefined") return;

  const current = document.currentScript?.src;
  if (current && !document.querySelector("link[data-rich-content-styles]")) {
    const styleUrl = new URL(current, window.location.href);
    styleUrl.pathname = styleUrl.pathname.replace(
      /conversation-rich-content\.js$/,
      "conversation-rich-content.css",
    );
    styleUrl.search = "?v=20260801-rich-content1";
    const link = document.createElement("link");
    link.rel = "stylesheet";
    link.href = styleUrl.toString();
    link.dataset.richContentStyles = "true";
    document.head.append(link);
  }

  const feed = document.querySelector("[data-conversation-feed]");
  if (!feed) return;

  const timers = new WeakMap();
  const markdownSignal = /(^|\n)(#{1,3}\s+|[-*]\s+|\d+\.\s+|>\s*|```)|\*\*[^*]+\*\*|`[^`]+`/;

  const copyText = async (value) => {
    const content = String(value || "");
    if (navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(content);
      return;
    }
    const proxy = document.createElement("textarea");
    proxy.className = "vh-clipboard-proxy";
    proxy.value = content;
    proxy.setAttribute("readonly", "");
    document.body.append(proxy);
    proxy.select();
    document.execCommand("copy");
    proxy.remove();
  };

  const temporaryLabel = (button, value) => {
    const original = button.dataset.originalLabel || button.textContent;
    button.dataset.originalLabel = original;
    button.textContent = value;
    window.setTimeout(() => {
      if (button.isConnected) button.textContent = original;
    }, 1400);
  };

  const appendInline = (parent, value) => {
    const source = String(value || "");
    const pattern = /(\*\*[^*]+\*\*|`[^`\n]+`)/g;
    let cursor = 0;
    for (const match of source.matchAll(pattern)) {
      if (match.index > cursor) parent.append(document.createTextNode(source.slice(cursor, match.index)));
      const token = match[0];
      if (token.startsWith("**")) {
        const strong = document.createElement("strong");
        strong.textContent = token.slice(2, -2);
        parent.append(strong);
      } else {
        const code = document.createElement("code");
        code.className = "vh-rich-inline-code";
        code.textContent = token.slice(1, -1);
        parent.append(code);
      }
      cursor = match.index + token.length;
    }
    if (cursor < source.length) parent.append(document.createTextNode(source.slice(cursor)));
  };

  const isBlockStart = (line) =>
    /^```/.test(line) || /^(#{1,3})\s+/.test(line) || /^[-*]\s+/.test(line) || /^\d+\.\s+/.test(line) || /^>\s*/.test(line);

  const codeBlock = (language, content) => {
    const wrapper = document.createElement("section");
    wrapper.className = "vh-rich-code";
    const header = document.createElement("header");
    const label = document.createElement("span");
    label.textContent = language || "code";
    const button = document.createElement("button");
    button.type = "button";
    button.className = "vh-rich-code-copy";
    button.textContent = "Copy code";
    button.setAttribute("aria-label", `Copy ${language || "code"} block`);
    button.addEventListener("click", async () => {
      try {
        await copyText(content);
        temporaryLabel(button, "Copied");
      } catch (_error) {
        temporaryLabel(button, "Copy failed");
      }
    });
    header.append(label, button);
    const pre = document.createElement("pre");
    const code = document.createElement("code");
    code.textContent = content;
    pre.append(code);
    wrapper.append(header, pre);
    return wrapper;
  };

  const renderBlocks = (raw) => {
    const fragment = document.createDocumentFragment();
    const lines = String(raw || "").replaceAll("\r\n", "\n").split("\n");
    let index = 0;

    while (index < lines.length) {
      const line = lines[index];
      if (!line.trim()) {
        index += 1;
        continue;
      }

      const fence = line.match(/^```([^`]*)$/);
      if (fence) {
        const language = fence[1].trim();
        const content = [];
        index += 1;
        while (index < lines.length && !/^```\s*$/.test(lines[index])) {
          content.push(lines[index]);
          index += 1;
        }
        if (index < lines.length) index += 1;
        fragment.append(codeBlock(language, content.join("\n")));
        continue;
      }

      const heading = line.match(/^(#{1,3})\s+(.+)$/);
      if (heading) {
        const level = Math.min(4, heading[1].length + 1);
        const element = document.createElement(`h${level}`);
        element.className = "vh-rich-heading";
        appendInline(element, heading[2]);
        fragment.append(element);
        index += 1;
        continue;
      }

      if (/^[-*]\s+/.test(line)) {
        const list = document.createElement("ul");
        list.className = "vh-rich-list";
        while (index < lines.length && /^[-*]\s+/.test(lines[index])) {
          const item = document.createElement("li");
          appendInline(item, lines[index].replace(/^[-*]\s+/, ""));
          list.append(item);
          index += 1;
        }
        fragment.append(list);
        continue;
      }

      if (/^\d+\.\s+/.test(line)) {
        const list = document.createElement("ol");
        list.className = "vh-rich-list";
        while (index < lines.length && /^\d+\.\s+/.test(lines[index])) {
          const item = document.createElement("li");
          appendInline(item, lines[index].replace(/^\d+\.\s+/, ""));
          list.append(item);
          index += 1;
        }
        fragment.append(list);
        continue;
      }

      if (/^>\s*/.test(line)) {
        const quote = document.createElement("blockquote");
        quote.className = "vh-rich-quote";
        const quoted = [];
        while (index < lines.length && /^>\s*/.test(lines[index])) {
          quoted.push(lines[index].replace(/^>\s*/, ""));
          index += 1;
        }
        appendInline(quote, quoted.join("\n"));
        fragment.append(quote);
        continue;
      }

      const paragraphLines = [];
      while (index < lines.length && lines[index].trim() && !isBlockStart(lines[index])) {
        paragraphLines.push(lines[index]);
        index += 1;
      }
      const paragraph = document.createElement("p");
      paragraph.className = "vh-rich-paragraph";
      appendInline(paragraph, paragraphLines.join("\n"));
      fragment.append(paragraph);
    }

    return fragment;
  };

  const renderCopy = (copy) => {
    if (!(copy instanceof HTMLElement)) return;
    const article = copy.closest(".vh-chat-message");
    if (!article?.classList.contains("is-assistant")) return;
    if (copy.dataset.richRendering === "true" || copy.dataset.richRendered === "true") return;

    const raw = copy.dataset.rawMessage || copy.textContent || "";
    copy.dataset.rawMessage = raw;
    if (!markdownSignal.test(raw)) {
      copy.dataset.richRendered = "plain";
      return;
    }

    copy.dataset.richRendering = "true";
    copy.replaceChildren(renderBlocks(raw));
    copy.dataset.richRendered = "true";
    copy.dataset.richRendering = "false";
  };

  const scheduleCopy = (copy, delay = 180) => {
    if (!(copy instanceof HTMLElement) || copy.dataset.richRendered === "true") return;
    const existing = timers.get(copy);
    if (existing) window.clearTimeout(existing);
    const timer = window.setTimeout(() => {
      timers.delete(copy);
      renderCopy(copy);
    }, delay);
    timers.set(copy, timer);
  };

  const scan = (delay = 0) => {
    feed.querySelectorAll(".vh-chat-message.is-assistant .vh-message-copy").forEach((copy) =>
      scheduleCopy(copy, delay),
    );
  };

  scan(0);
  new MutationObserver((mutations) => {
    const copies = new Set();
    mutations.forEach((mutation) => {
      const element = mutation.target instanceof Element ? mutation.target : mutation.target.parentElement;
      const copy = element?.closest?.(".vh-message-copy");
      if (copy) copies.add(copy);
      mutation.addedNodes.forEach((node) => {
        if (!(node instanceof Element)) return;
        if (node.matches(".vh-message-copy")) copies.add(node);
        node.querySelectorAll?.(".vh-message-copy").forEach((item) => copies.add(item));
      });
    });
    copies.forEach((copy) => scheduleCopy(copy));
  }).observe(feed, { childList: true, characterData: true, subtree: true });
})();