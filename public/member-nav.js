(() => {
    const navigation = document.querySelector("[data-member-navigation]");
    if (!navigation) return;

    fetch("/api/me", { credentials: "same-origin" })
        .then(response => response.ok ? response.json() : null)
        .then(data => {
            if (data?.success && data.user?.role === "user") {
                navigation.classList.remove("hidden");
                navigation.classList.add("flex");
            }
        })
        .catch(() => {});
})();