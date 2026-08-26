(() => {
  const state = document.getElementById("discovery-state");
  const interactive = document.getElementById("discovery-interactive");
  const title = document.getElementById("play-title");
  const statusMessage = document.getElementById("interaction-status");
  if (!state || !interactive || !title) return;

  const sessionId = state.dataset.sessionId;
  const labels = [
    ["yes", "是"],
    ["probably_yes", "大概是"],
    ["unknown", "不知道"],
    ["probably_no", "大概不是"],
    ["no", "不是"],
  ];

  function element(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = text;
    return node;
  }

  function linkHome() {
    const link = element("a", "button-link", "重新开始");
    link.href = "/";
    return link;
  }

  function setStatus(message) {
    if (statusMessage) statusMessage.textContent = message || "";
  }

  function render(payload) {
    if (payload.state === "VERIFICATION" && !Object.prototype.hasOwnProperty.call(payload, "challenge")) {
      fetch(`/api/public/sessions/${sessionId}/challenge`)
        .then((response) => {
          if (!response.ok) throw new Error("challenge request failed");
          return response.json();
        })
        .then(render)
        .catch(() => {
          interactive.replaceChildren(element("p", "lede", "暂时无法加载验证问题，请刷新后重试。"));
        });
      return;
    }
    interactive.replaceChildren();
    setStatus("");
    title.textContent = payload.state === "QUESTION" ? "回答一个问题" : payload.state === "GUESS" ? "我有一个猜测" : payload.state === "UNABLE_TO_IDENTIFY" ? "暂时无法确定身份" : payload.state === "LOCKED" ? "本次识别已锁定" : payload.state === "EXPIRED" ? "本次识别已过期" : payload.state === "VERIFICATION" ? "进入身份验证" : payload.state === "VERIFIED" ? "你的内容已解锁" : "识别完成";
    if (payload.state === "QUESTION" && payload.question) {
      interactive.append(element("p", "question-text", payload.question.text));
      interactive.append(element("p", "question-helper", "选择最接近真实情况的答案即可，不需要解释原因。"));
      const form = element("form", "answer-form");
      form.dataset.questionId = payload.question.id;
      form.action = `/play/${sessionId}/answer`;
      form.method = "post";
      labels.forEach(([value, label]) => {
        const button = element("button", "", label);
        button.type = "submit";
        button.name = "answer";
        button.value = value;
        form.append(button);
      });
      interactive.append(form);
    } else if (payload.state === "GUESS" && payload.guess) {
      interactive.append(element("p", "question-text", `我猜你是：${payload.guess.display_name}`));
      interactive.append(element("p", "question-helper", "请确认这是不是为你准备的内容。"));
      const actions = element("div", "answer-form");
      [[true, "是我"], [false, "不是我"]].forEach(([accepted, label]) => {
        const form = element("form");
        form.dataset.accepted = String(accepted);
        form.action = `/play/${sessionId}/guess`;
        form.method = "post";
        const button = element("button", "", label);
        button.type = "submit";
        form.append(button);
        actions.append(form);
      });
      interactive.append(actions);
    } else if (payload.state === "UNABLE_TO_IDENTIFY") {
      interactive.append(element("p", "lede", "当前答案不足以可靠确定身份。我们不会强行猜测。"), linkHome());
    } else if (payload.state === "LOCKED") {
      interactive.append(element("p", "lede", "多次拒绝后，本次识别已安全锁定。"), linkHome());
    } else if (payload.state === "EXPIRED") {
      interactive.append(element("p", "lede", "为了保护隐私，本次识别已过期。"), linkHome());
    } else if (payload.state === "VERIFIED") {
      const cover = element("section", "delivery-cover");
      cover.append(element("span", "content-type-label", payload.content_type_label || "内容"));
      cover.append(element("h2", "", payload.cover_title || "一份只属于你的内容"));
      cover.append(element("p", "", payload.opening || "如果你正在看到这段话，说明这份内容已经为你打开。"));
      cover.append(element("p", "signature", `— ${payload.signature || "Still Alive"}`));
      interactive.append(cover, element("p", "lede", "你的内容已解锁。下载链接会在短时间后失效，每个链接只能使用有限次数。"));
      if (payload.assets && payload.assets.length) {
        const sectionTitle = element("div", "delivery-section-title");
        sectionTitle.append(element("h2", "", "为你准备的内容"), element("span", "muted", `${payload.assets.length} 项`));
        interactive.append(sectionTitle);
        const list = element("ul", "asset-list");
        payload.assets.forEach((asset) => {
          const item = element("li");
          item.append(element("span", "", `${asset.display_name} · ${asset.size} bytes`));
          const form = element("form");
          form.action = `/play/${sessionId}/assets/${asset.id}/grant`;
          form.method = "post";
          form.dataset.grant = asset.id;
          const button = element("button", "", "下载");
          button.type = "submit";
          form.append(button);
          item.append(form);
          list.append(item);
        });
        interactive.append(list);
      } else {
        interactive.append(element("p", "muted", "当前没有可用内容。"));
      }
    } else if (payload.state === "VERIFICATION") {
      if (payload.challenge) {
        interactive.append(element("p", "lede", "请回答专属验证问题。正确答案不会显示在页面上。"));
        if (payload.message) interactive.append(element("p", "verification-feedback", payload.message));
        interactive.append(element("p", "question-text", payload.challenge.prompt));
        const retryAfter = Number(payload.challenge.retry_after_seconds || 0);
        interactive.append(element("p", "verification-meta", retryAfter > 0 ? `还可尝试 ${payload.challenge.attempts_remaining} 次。请等待 ${retryAfter} 秒后再试。` : `还可尝试 ${payload.challenge.attempts_remaining} 次。连续答错会触发保护锁定，锁定后需要重新开始。`));
        const form = element("form", "answer-form");
        form.dataset.verify = "true";
        form.action = `/play/${sessionId}/verify`;
        form.method = "post";
        const challenge = element("input");
        challenge.type = "hidden";
        challenge.name = "challenge_id";
        challenge.value = payload.challenge.id;
        const input = element("input");
        input.name = "answer";
        input.autocomplete = "off";
        input.required = true;
        input.disabled = retryAfter > 0;
        const label = element("label", "", "答案");
        label.append(input);
        form.append(challenge, label);
        const button = element("button", "", "提交验证");
        button.type = "submit";
        button.disabled = retryAfter > 0;
        form.append(button);
        interactive.append(form);
        if (retryAfter > 0) {
          window.setTimeout(() => render({ ...payload, challenge: { ...payload.challenge, retry_after_seconds: 0 } }), retryAfter * 1000);
        }
      } else {
        interactive.append(element("p", "lede", payload.message || "识别结果已确认，但尚未配置专属验证问题。"));
      }
    } else {
      interactive.append(element("p", "lede", "本次流程已完成。"));
    }
  }

  interactive.addEventListener("submit", async (event) => {
    const form = event.target;
    if (!form.dataset.questionId && !form.dataset.verify && !form.dataset.accepted && !form.dataset.grant) return;
    event.preventDefault();
    let url;
    let body;
    if (form.dataset.grant) {
      url = `/api/public/sessions/${sessionId}/assets/${form.dataset.grant}/grant`;
    } else if (form.dataset.questionId) {
      url = `/api/public/sessions/${sessionId}/answers`;
      body = { question_id: form.dataset.questionId, answer: form.querySelector("button[type=submit][value]")?.value || "unknown" };
    } else if (form.dataset.verify) {
      url = `/api/public/sessions/${sessionId}/verify`;
      body = { challenge_id: form.querySelector("[name=challenge_id]")?.value, answer: form.querySelector("[name=answer]")?.value || "" };
    } else {
      url = `/api/public/sessions/${sessionId}/guess`;
      body = { accepted: form.dataset.accepted === "true" };
    }
    const submitter = event.submitter;
    if (form.dataset.questionId && submitter) body.answer = submitter.value;
    try {
      setStatus(form.dataset.grant ? "正在生成安全下载链接…" : "正在提交答案…");
      Array.from(form.querySelectorAll("button")).forEach((button) => { button.disabled = true; });
      const options = { method: "POST" };
      if (body !== undefined) {
        options.headers = { "Content-Type": "application/json" };
        options.body = JSON.stringify(body);
      }
      const response = await fetch(url, options);
      if (response.status === 429) {
        const retryAfter = Math.max(1, Number(response.headers.get("Retry-After") || 1));
        setStatus(`验证暂时被保护，请等待 ${retryAfter} 秒后再试。`);
        window.setTimeout(() => {
          Array.from(form.querySelectorAll("button, input")).forEach((control) => { control.disabled = false; });
          setStatus("冷却已结束，可以再次提交。");
        }, retryAfter * 1000);
        return;
      }
      if (!response.ok) throw new Error("request failed");
      if (form.dataset.grant) {
        const grant = await response.json();
        const expires = grant.expires_at ? new Date(grant.expires_at).toLocaleTimeString() : "短时间内";
        setStatus(`下载链接已生成，有效期至 ${expires}，正在开始下载…`);
        window.setTimeout(() => window.location.assign(grant.download_url), 250);
        return;
      }
      render(await response.json());
    } catch (_error) {
      setStatus("网络请求失败，正在切换为普通表单提交…");
      form.submit();
    }
  });
})();
