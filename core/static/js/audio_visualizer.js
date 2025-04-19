// Wait until the DOM and audio are fully ready
window.addEventListener("DOMContentLoaded", () => {
    const remoteAudio = document.getElementById("remoteAudio");

    // Create a visual line
    const visualLine = document.createElement("div");
    visualLine.style.width = "12px";
    visualLine.style.height = "20px";
    visualLine.style.backgroundColor = "green";
    visualLine.style.margin = "10px auto";
    visualLine.style.transition = "height 0.1s ease";
    document.body.appendChild(visualLine);

    const context = new (window.AudioContext || window.webkitAudioContext)();
    const analyser = context.createAnalyser();
    analyser.fftSize = 256;
    const dataArray = new Uint8Array(analyser.frequencyBinCount);

    const source = context.createMediaElementSource(remoteAudio);
    source.connect(analyser);
    analyser.connect(context.destination);

    function animate() {
        requestAnimationFrame(animate);
        analyser.getByteFrequencyData(dataArray);

        // Measure volume (average of frequency bins)
        let volume = dataArray.reduce((sum, val) => sum + val, 0) / dataArray.length;
        let scaledHeight = Math.min(100, volume / 2 + 10); // scale & cap height

        visualLine.style.height = `${scaledHeight}px`;
    }

    animate();
});
