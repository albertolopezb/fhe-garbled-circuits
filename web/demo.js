const suspectButtons = document.querySelectorAll(".demo-picker button");

for (const button of suspectButtons) {
  button.addEventListener("click", () => {
    document.body.dataset.activeSuspect = button.dataset.account;
    for (const option of suspectButtons) {
      const selected = option === button;
      option.setAttribute("aria-pressed", String(selected));
      const frame = document.getElementById(option.getAttribute("aria-controls"));
      frame.hidden = !selected;
      if (selected) {
        frame.contentWindow.postMessage("pp-demo-pane-active", location.origin);
      }
    }
  });
}
