let coinInterval = setInterval(async () => {
    try {
        const response = await fetch('/deduct-coins/', {
            method: 'POST',
            headers: {
                'X-CSRFToken': '{{ csrf_token }}',
                'Content-Type': 'application/json'
            }
        });
        const data = await response.json();

        if (data.end_call) {
            alert("Call ended due to insufficient coins.");
            window.location.href = "/online/";
        } else {
            document.getElementById("coinDisplay").textContent = `Coins: ${data.coins}`;
        }

    } catch (err) {
        console.error("Coin update error:", err);
    }
}, 60000); // every 60 seconds
