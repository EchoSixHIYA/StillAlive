(() => {
  const search = document.querySelector("[data-people-search]");
  const status = document.querySelector("[data-people-status]");
  const cards = Array.from(document.querySelectorAll("[data-person-card]"));
  if (!search || !status || !cards.length) return;

  const update = () => {
    const query = search.value.trim().toLocaleLowerCase();
    const selectedStatus = status.value;
    let visibleCount = 0;
    cards.forEach((card) => {
      const name = (card.dataset.personName || "").toLocaleLowerCase();
      const matchesName = !query || name.includes(query);
      const matchesStatus = selectedStatus === "all" || card.dataset.personStatus === selectedStatus;
      const visible = matchesName && matchesStatus;
      card.hidden = !visible;
      if (visible) visibleCount += 1;
    });
    const count = document.querySelector("[data-people-count]");
    if (count) count.textContent = `${visibleCount} 位人物`;
    const empty = document.querySelector("[data-filter-empty]");
    if (empty) empty.hidden = visibleCount !== 0;
  };

  search.addEventListener("input", update);
  status.addEventListener("change", update);
})();
