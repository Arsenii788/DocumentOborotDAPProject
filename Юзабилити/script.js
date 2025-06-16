document.addEventListener('DOMContentLoaded', function() {
    // Переключение темы
    const themeToggle = document.getElementById('theme-toggle');
    themeToggle.addEventListener('click', toggleTheme);
    
    // Проверяем сохраненную тему в localStorage
    const savedTheme = localStorage.getItem('theme') || 'light';
    document.documentElement.setAttribute('data-theme', savedTheme);
    
    // Масштабирование страницы
    const zoomInBtn = document.getElementById('zoom-in');
    const zoomOutBtn = document.getElementById('zoom-out');
    zoomInBtn.addEventListener('click', zoomIn);
    zoomOutBtn.addEventListener('click', zoomOut);
    
    // Проверяем сохраненный масштаб
    const savedZoom = localStorage.getItem('zoom') || 1000;
    document.body.style.zoom = savedZoom + '%';
    
    // Выход из системы
    const logoutBtn = document.getElementById('logout-btn');
    logoutBtn.addEventListener('click', logout);
    
    // Поиск
    const searchBtn = document.querySelector('.search-btn');
    searchBtn.addEventListener('click', performSearch);
    
    // Обработка отправки формы контактов
    const contactForm = document.querySelector('.contact-form form');
    if (contactForm) {
        contactForm.addEventListener('submit', handleFormSubmit);
    }
});

function toggleTheme() {
    const currentTheme = document.documentElement.getAttribute('data-theme');
    const newTheme = currentTheme === 'light' ? 'dark' : 'light';
    
    document.documentElement.setAttribute('data-theme', newTheme);
    localStorage.setItem('theme', newTheme);
}

function zoomIn() {
    let currentZoom = parseInt(document.body.style.zoom) || 100;
    if (currentZoom < 150) {
        currentZoom += 10;
        document.body.style.zoom = currentZoom + '%';
        localStorage.setItem('zoom', currentZoom);
    }
}

function zoomOut() {
    let currentZoom = parseInt(document.body.style.zoom) || 100;
    if (currentZoom > 50) {
        currentZoom -= 10;
        document.body.style.zoom = currentZoom + '%';
        localStorage.setItem('zoom', currentZoom);
    }
}

function logout() {
    // Здесь может быть вызов API для выхода из системы
    alert('Вы успешно вышли из системы');
    // Перенаправление на страницу входа
    window.location.href = 'login.html'; // У вас может быть другая страница входа
}

function performSearch() {
    const searchInput = document.querySelector('.search-box input');
    const query = searchInput.value.trim();
    
    if (query) {
        alert(`Выполняется поиск: ${query}`);
        // Здесь может быть перенаправление на страницу результатов поиска
        // или AJAX-запрос для динамического поиска
    } else {
        alert('Пожалуйста, введите поисковый запрос');
    }
}

function handleFormSubmit(e) {
    e.preventDefault();
    
    const formData = {
        name: document.getElementById('name').value,
        email: document.getElementById('email').value,
        subject: document.getElementById('subject').value,
        message: document.getElementById('message').value
    };
    
    // Здесь может быть отправка формы на сервер
    console.log('Форма отправлена:', formData);
    alert('Спасибо за ваше сообщение! Мы свяжемся с вами в ближайшее время.');
    
    // Очистка формы
    e.target.reset();
}