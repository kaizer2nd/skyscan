// ===== Starry Background Animation =====
// GitHub Copilot inspired particle animation

class StarryBackground {
    constructor() {
        this.canvas = document.getElementById('starry-bg');
        if (!this.canvas) return;
        
        this.ctx = this.canvas.getContext('2d');
        this.stars = [];
        this.shootingStars = [];
        this.resize();
        this.init();
        this.animate();
        this.setupScrollListener();
        
        window.addEventListener('resize', () => this.resize());
    }
    
    resize() {
        this.canvas.width = window.innerWidth;
        this.canvas.height = window.innerHeight;
    }
    
    init() {
        // Create static stars
        const starCount = 200;
        for (let i = 0; i < starCount; i++) {
            this.stars.push({
                x: Math.random() * this.canvas.width,
                y: Math.random() * this.canvas.height,
                size: Math.random() * 2,
                opacity: Math.random(),
                twinkleSpeed: Math.random() * 0.02
            });
        }
    }
    
    createShootingStar() {
        if (Math.random() > 0.98) {
            this.shootingStars.push({
                x: Math.random() * this.canvas.width,
                y: Math.random() * this.canvas.height / 2,
                length: Math.random() * 80 + 40,
                speed: Math.random() * 10 + 5,
                opacity: 1
            });
        }
    }
    
    drawStars() {
        this.stars.forEach(star => {
            this.ctx.beginPath();
            this.ctx.arc(star.x, star.y, star.size, 0, Math.PI * 2);
            this.ctx.fillStyle = `rgba(0, 212, 255, ${star.opacity})`;
            this.ctx.fill();
            
            // Twinkling effect
            star.opacity += star.twinkleSpeed;
            if (star.opacity >= 1 || star.opacity <= 0) {
                star.twinkleSpeed = -star.twinkleSpeed;
            }
        });
    }
    
    drawShootingStars() {
        this.shootingStars.forEach((star, index) => {
            const gradient = this.ctx.createLinearGradient(
                star.x, star.y,
                star.x + star.length, star.y + star.length
            );
            gradient.addColorStop(0, `rgba(0, 212, 255, ${star.opacity})`);
            gradient.addColorStop(1, 'rgba(0, 212, 255, 0)');
            
            this.ctx.beginPath();
            this.ctx.moveTo(star.x, star.y);
            this.ctx.lineTo(star.x + star.length, star.y + star.length);
            this.ctx.strokeStyle = gradient;
            this.ctx.lineWidth = 2;
            this.ctx.stroke();
            
            star.x += star.speed;
            star.y += star.speed;
            star.opacity -= 0.01;
            
            if (star.opacity <= 0) {
                this.shootingStars.splice(index, 1);
            }
        });
    }
    
    animate() {
        this.ctx.clearRect(0, 0, this.canvas.width, this.canvas.height);
        this.drawStars();
        this.drawShootingStars();
        this.createShootingStar();
        requestAnimationFrame(() => this.animate());
    }
    
    setupScrollListener() {
        window.addEventListener('scroll', () => {
            const scrollY = window.scrollY;
            const fadeStart = 100;
            const fadeEnd = 600;
            
            if (scrollY < fadeStart) {
                this.canvas.style.opacity = '1';
            } else if (scrollY >= fadeEnd) {
                this.canvas.style.opacity = '0';
            } else {
                const opacity = 1 - (scrollY - fadeStart) / (fadeEnd - fadeStart);
                this.canvas.style.opacity = opacity.toString();
            }
        });
    }
}

// Initialize when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => new StarryBackground());
} else {
    new StarryBackground();
}

// ===== Scroll Reveal for Feature Cards =====
const observerOptions = {
    threshold: 0.2,
    rootMargin: '0px 0px -50px 0px'
};

const observer = new IntersectionObserver((entries) => {
    entries.forEach((entry, index) => {
        if (entry.isIntersecting) {
            setTimeout(() => {
                entry.target.classList.add('reveal');
            }, index * 100);
            observer.unobserve(entry.target);
        }
    });
}, observerOptions);

// Observe feature cards when DOM is ready
window.addEventListener('DOMContentLoaded', () => {
    const featureCards = document.querySelectorAll('.feature-card');
    featureCards.forEach(card => observer.observe(card));
});
