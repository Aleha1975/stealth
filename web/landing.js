// Old pay links (/stealth/?to=…) open the app directly.
if (new URLSearchParams(location.search).has("to")) location.replace("./app.html" + location.search + location.hash);
