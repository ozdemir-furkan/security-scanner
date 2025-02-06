document.addEventListener('DOMContentLoaded', function() {
    const searchTypeBtn = document.getElementById('searchTypeBtn');
    const searchTypeDropdown = document.getElementById('searchTypeDropdown');
    const searchTypeOptions = document.querySelectorAll('.search-type-option');
    const selectedType = document.getElementById('selectedType');
    const scanTypeInput = document.getElementById('scan_type');
    const searchInput = document.getElementById('searchInput');
    const searchForm = document.getElementById('searchForm');

    // Dropdown toggle
    searchTypeBtn.addEventListener('click', function(e) {
        e.stopPropagation();  // Event bubbling'i durdur
        searchTypeDropdown.style.display = searchTypeDropdown.style.display === 'block' ? 'none' : 'block';
    });

    // Close dropdown when clicking outside
    document.addEventListener('click', function(event) {
        if (!event.target.closest('.search-type-selector')) {
            searchTypeDropdown.style.display = 'none';
        }
    });

    // Handle option selection
    searchTypeOptions.forEach(option => {
        option.addEventListener('click', function(e) {
            e.stopPropagation();  // Event bubbling'i durdur
            const type = this.dataset.type;
            selectedType.textContent = this.textContent.trim();
            scanTypeInput.value = type;
            searchTypeDropdown.style.display = 'none';

            // Input type'ı resetle
            searchInput.type = 'text';
            
            // Update placeholder based on selected type
            switch(type) {
                case 'ip':
                    searchInput.placeholder = 'IP adresi veya domain girin...';
                    break;
                case 'dork':
                    searchInput.placeholder = 'Aranacak kelimeyi girin...';
                    break;
                case 'password':
                    searchInput.type = 'password';
                    searchInput.placeholder = 'Kontrol edilecek şifreyi girin...';
                    break;
                case 'whois':
                    searchInput.placeholder = 'Domain adresini girin...';
                    break;
            }
        });
    });

    // Form submission
    searchForm.addEventListener('submit', function(e) {
        if (!scanTypeInput.value) {
            e.preventDefault();
            alert('Lütfen bir tarama türü seçin!');
        }
    });
}); 