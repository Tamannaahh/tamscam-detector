document.addEventListener('DOMContentLoaded', () => {
    const form = document.getElementById('scamScoreForm');
    if (!form) return;

    const analyzeBtn = document.getElementById('analyzeBtn');
    const btnText = document.getElementById('btnText');
    const btnSpinner = document.getElementById('btnSpinner');

    const scoreValue = document.getElementById('scoreValue');
    const scoreCircle = document.getElementById('scoreCircle');
    const verdictPill = document.getElementById('verdictPill');
    const verdictDesc = document.getElementById('verdictDesc');

    form.addEventListener('submit', async function (e) {
        // PREVENT PAGE RELOAD / BLANKING
        e.preventDefault();
        e.stopPropagation();

        const title = document.getElementById('jobTitle') ? document.getElementById('jobTitle').value.trim() : '';
        const company = document.getElementById('companyName') ? document.getElementById('companyName').value.trim() : '';
        const location = document.getElementById('location') ? document.getElementById('location').value.trim() : '';
        const salary = document.getElementById('salaryRange') ? document.getElementById('salaryRange').value.trim() : '';
        const empType = document.getElementById('empType') ? document.getElementById('empType').value.trim() : '';
        const expLevel = document.getElementById('expLevel') ? document.getElementById('expLevel').value.trim() : '';
        const companyProfile = document.getElementById('companyProfile') ? document.getElementById('companyProfile').value.trim() : '';
        const desc = document.getElementById('jobDesc') ? document.getElementById('jobDesc').value.trim() : '';

        if (!title || !desc) {
            alert('Please fill in both Job Title and Job Description.');
            return false;
        }

        // UI Loading State
        if (btnText) btnText.style.display = 'none';
        if (btnSpinner) btnSpinner.classList.remove('hidden');
        if (analyzeBtn) analyzeBtn.disabled = true;

        try {
            const response = await fetch('/api/analyze', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json'
                },
                body: JSON.stringify({
                    title: title,
                    company: company,
                    location: location,
                    salary: salary,
                    empType: empType,
                    expLevel: expLevel,
                    companyProfile: companyProfile,
                    description: desc
                })
            });

            const result = await response.json();

            if (response.ok) {
                // 1. Animate Radial Score
                animateScore(result.score, result.status, result.verdict, result.reason);

                // 2. Run Heuristic Checklist
                const fullText = `${title} ${company} ${location} ${salary} ${companyProfile} ${desc}`;
                runHeuristics(fullText);

                // 3. Prepend to Recent Scans Table
                prependScanRow(result);
            } else {
                alert(result.error || 'Evaluation failed on server.');
            }
        } catch (err) {
            console.error('Error analyzing post:', err);
            alert('Failed to connect to the analysis backend. Check your Flask terminal for errors.');
        } finally {
            if (btnText) btnText.style.display = 'inline';
            if (btnSpinner) btnSpinner.classList.add('hidden');
            if (analyzeBtn) analyzeBtn.disabled = false;
        }

        return false;
    });

    function animateScore(score, status, verdict, reason) {
        if (!scoreCircle || !scoreValue) return;

        const circumference = 440;
        const offset = circumference - (score / 100) * circumference;

        scoreCircle.style.strokeDashoffset = offset;

        let color = '#10b981'; // Green (Safe)
        if (status === 'warning') color = '#f59e0b'; // Amber (Suspicious)
        if (status === 'danger') color = '#f43f5e';  // Red (High Risk)

        scoreCircle.style.stroke = color;
        scoreValue.style.color = color;

        let current = 0;
        const step = Math.max(1, Math.floor(score / 30));
        const interval = setInterval(() => {
            current += step;
            if (current >= score) {
                clearInterval(interval);
                scoreValue.innerText = score;
            } else {
                scoreValue.innerText = current;
            }
        }, 20);

        if (verdictPill) {
            verdictPill.innerText = verdict.toUpperCase();
            verdictPill.style.backgroundColor = `${color}25`;
            verdictPill.style.color = color;
        }

        if (verdictDesc) {
            verdictDesc.innerText = reason;
        }
    }

    function runHeuristics(text) {
        const lower = text.toLowerCase();

        // Check Payment
        const checkPayment = document.querySelector('#checkPayment strong');
        if (checkPayment) {
            if (lower.includes('fee') || lower.includes('wire') || lower.includes('deposit') || lower.includes('crypto') || lower.includes('gift card')) {
                checkPayment.innerText = 'Detected';
                checkPayment.className = 'badge-danger';
            } else {
                checkPayment.innerText = 'Clear';
                checkPayment.className = 'badge-clean';
            }
        }

        // Check Channels
        const checkChannels = document.querySelector('#checkChannels strong');
        if (checkChannels) {
            if (lower.includes('telegram') || lower.includes('whatsapp') || lower.includes('signal')) {
                checkChannels.innerText = 'Suspicious';
                checkChannels.className = 'badge-danger';
            } else {
                checkChannels.innerText = 'Standard';
                checkChannels.className = 'badge-clean';
            }
        }

        // Check Salary
        const checkSalary = document.querySelector('#checkSalary strong');
        if (checkSalary) {
            if (lower.includes('$500/day') || lower.includes('$50/hr') || lower.includes('no experience required') || lower.includes('instant hiring')) {
                checkSalary.innerText = 'Unusual';
                checkSalary.className = 'badge-danger';
            } else {
                checkSalary.innerText = 'Realistic';
                checkSalary.className = 'badge-clean';
            }
        }

        // Check Domain
        const checkDomain = document.querySelector('#checkDomain strong');
        if (checkDomain) {
            if (lower.includes('@gmail.com') || lower.includes('@yahoo.com') || lower.includes('@hotmail.com')) {
                checkDomain.innerText = 'Free Webmail';
                checkDomain.className = 'badge-danger';
            } else {
                checkDomain.innerText = 'Standard';
                checkDomain.className = 'badge-clean';
            }
        }
    }

    function prependScanRow(data) {
        const tbody = document.querySelector('#scansTable tbody');
        if (!tbody) return;

        const emptyRow = document.getElementById('noScansRow');
        if (emptyRow) emptyRow.remove();

        const tr = document.createElement('tr');
        tr.className = 'animate-slide-up';
        tr.innerHTML = `
            <td>${data.timestamp}</td>
            <td class="font-bold">${escapeHtml(data.title)}</td>
            <td>${escapeHtml(data.company)}</td>
            <td>
                <div class="score-tag score-tag-${data.status}">
                    ${data.score} / 100
                </div>
            </td>
            <td>
                <span class="status-badge status-${data.status}">
                    ${data.verdict}
                </span>
            </td>
        `;
        tbody.prepend(tr);
    }

    function escapeHtml(str) {
        return String(str).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
    }
});