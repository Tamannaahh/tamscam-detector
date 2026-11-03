document.addEventListener('DOMContentLoaded', () => {
    const forms = document.querySelectorAll('.strict-validate');
    const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&#])[A-Za-z\d@$!%*?&#]{8,}$/;

    forms.forEach(form => {
        form.addEventListener('submit', (e) => {
            let isValid = true;
            const requiredFields = form.querySelectorAll('input[required], textarea[required]');

            // Remove existing inline error messages
            form.querySelectorAll('.error-text').forEach(el => el.remove());

            requiredFields.forEach(field => {
                field.classList.remove('field-error');
                const val = field.value.trim();

                if (!val) {
                    isValid = false;
                    field.classList.add('field-error');
                    renderError(field, 'This field is strictly required.');
                } else if (field.type === 'email' && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(val)) {
                    isValid = false;
                    field.classList.add('field-error');
                    renderError(field, 'Enter a valid email address.');
                }
            });

            // Password Complexity Check
            const pass = form.querySelector('#password');
            if (pass && form.querySelector('#confirm_password')) {
                if (pass.value && !passwordRegex.test(pass.value)) {
                    isValid = false;
                    pass.classList.add('field-error');
                    renderError(pass, 'Requires 8+ chars, 1 uppercase, 1 lowercase, 1 digit, & 1 symbol (@$!%*?&#).');
                }
            }

            // Password Match Check
            const confirmPass = form.querySelector('#confirm_password');
            if (pass && confirmPass && pass.value && confirmPass.value) {
                if (pass.value !== confirmPass.value) {
                    isValid = false;
                    confirmPass.classList.add('field-error');
                    renderError(confirmPass, 'Passwords do not match.');
                }
            }

            if (!isValid) {
                e.preventDefault();
                e.stopPropagation();
            }
        });

        // Clear error style as user types
        form.querySelectorAll('input, textarea').forEach(input => {
            input.addEventListener('input', () => {
                input.classList.remove('field-error');
                const msg = input.parentElement.querySelector('.error-text');
                if (msg) msg.remove();
            });
        });
    });

    function renderError(element, message) {
        const errorSpan = document.createElement('span');
        errorSpan.className = 'error-text';
        errorSpan.innerText = message;
        element.parentElement.appendChild(errorSpan);
    }
});