// Hero/nav links: open the requested tab (the tab buttons are owned by app.js), then let the anchor scroll.
document.querySelectorAll("[data-go]").forEach(a => a.addEventListener("click", () => {
  const b = document.querySelector('.tabs [data-pane="' + a.dataset.go + '"]'); if (b) b.click();
}));
