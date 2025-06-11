(() => {
  // 키워드 리스트 확장 (약 40개 이상)
  const keywords = [
    "SQL Injection",
    "Cross-Site Scripting (XSS)",
    "Malware",
    "Phishing",
    "Ransomware",
    "Zero-Day",
    "Buffer Overflow",
    "DDoS",
    "Brute Force Attack",
    "Man-in-the-Middle",
    "Cryptojacking",
    "Social Engineering",
    "Password Attack",
    "Privilege Escalation",
    "Firewall",
    "Encryption",
    "Two-Factor Authentication",
    "VPN",
    "Penetration Testing",
    "Access Control",
    "Data Breach",
    "Patch Management",
    "Insider Threat",
    "Botnet",
    "Rootkit",
    "Security Information and Event Management (SIEM)",
    "Intrusion Detection System (IDS)",
    "Public Key Infrastructure (PKI)",
    "Distributed Ledger Technology (Blockchain)",
    "Identity Theft",
    "Threat Hunting",
    "Zero Trust",
    "Secure Coding",
    "Network Segmentation",
    "Cloud Security",
    "Endpoint Protection",
    "Security Policy",
    "Incident Response",
    "Vulnerability Assessment",
    "Security Awareness Training"
  ];

  // 보안 기사 데이터 (각 기사에 이미지 포함)
  const securityArticles = [
    {
      title: "SQL Injection 공격 방어 방법",
      content: "SQL Injection은 공격자가 악의적인 SQL 코드를 삽입해 데이터베이스를 조작하는 공격 기법입니다. Prepared Statement 사용이 핵심 방어 방법입니다.",
      tags: ["SQL Injection", "Database", "Security"],
      image: "https://upload.wikimedia.org/wikipedia/commons/thumb/0/02/SQL_injection.svg/320px-SQL_injection.svg.png"
    },
    {
      title: "Cross-Site Scripting(XSS) 이해 및 대응",
      content: "XSS는 웹 페이지에 악성 스크립트를 삽입해 사용자 세션을 탈취하거나 악성 행위를 수행하는 공격입니다. 입력값 검증과 Content Security Policy가 중요합니다.",
      tags: ["XSS", "Web Security", "Script"],
      image: "https://upload.wikimedia.org/wikipedia/commons/thumb/f/f5/Cross-site_scripting_-_XSS.svg/320px-Cross-site_scripting_-_XSS.svg.png"
    },
    {
      title: "Malware 종류와 감염 예방",
      content: "Malware는 바이러스, 웜, 트로이목마 등 여러 형태가 있으며, 최신 백신 프로그램 사용과 의심스러운 링크 클릭 금지가 중요합니다.",
      tags: ["Malware", "Virus", "Prevention"],
      image: "https://upload.wikimedia.org/wikipedia/commons/thumb/0/07/Virus_icon.svg/320px-Virus_icon.svg.png"
    },
    {
      title: "Phishing 공격 탐지 및 차단",
      content: "Phishing은 가짜 사이트를 통해 사용자의 민감 정보를 탈취하는 기법으로, URL 확인과 2단계 인증이 효과적입니다.",
      tags: ["Phishing", "Email Security", "Authentication"],
      image: "https://upload.wikimedia.org/wikipedia/commons/thumb/7/7f/Phishing_Attack.svg/320px-Phishing_Attack.svg.png"
    },
    {
      title: "방화벽(Firewall)의 역할과 설정",
      content: "방화벽은 네트워크 접근을 통제해 외부 공격으로부터 시스템을 보호합니다. 올바른 정책 설정이 중요합니다.",
      tags: ["Firewall", "Network Security", "Access Control"],
      image: "https://upload.wikimedia.org/wikipedia/commons/thumb/7/7a/Firewall.svg/320px-Firewall.svg.png"
    },
    {
      title: "암호화(Encryption) 기본 개념과 중요성",
      content: "데이터 암호화는 정보 유출 시에도 내용을 보호하는 핵심 기술입니다. 대칭키와 공개키 방식이 존재합니다.",
      tags: ["Encryption", "Cryptography", "Data Security"],
      image: "https://upload.wikimedia.org/wikipedia/commons/thumb/2/2b/Encryption_icon.svg/320px-Encryption_icon.svg.png"
    },
    {
      title: "VPN 사용과 보안 효과",
      content: "VPN은 공용 네트워크 사용 시 데이터 전송을 암호화하여 안전하게 보호합니다.",
      tags: ["VPN", "Network Security", "Privacy"],
      image: "https://upload.wikimedia.org/wikipedia/commons/thumb/8/81/Virtual_private_network_icon.svg/320px-Virtual_private_network_icon.svg.png"
    },
    {
      title: "제로 트러스트 보안 모델 소개",
      content: "제로 트러스트는 내부와 외부 모두 신뢰하지 않는 원칙으로, 모든 접근 요청을 엄격히 검증하는 보안 모델입니다.",
      tags: ["Zero Trust", "Network Security", "Access Control"],
      image: "https://upload.wikimedia.org/wikipedia/commons/thumb/9/98/Zero_Trust_icon.svg/320px-Zero_Trust_icon.svg.png"
    },
    {
      title: "침입 탐지 시스템(IDS) 개요",
      content: "IDS는 네트워크와 시스템 내 침입 시도를 모니터링하고 경고를 제공하는 보안 솔루션입니다.",
      tags: ["IDS", "Intrusion Detection", "Network Security"],
      image: "https://upload.wikimedia.org/wikipedia/commons/thumb/3/3d/Intrusion_detection_system_icon.svg/320px-Intrusion_detection_system_icon.svg.png"
    },
    {
      title: "보안 인식 교육(Security Awareness Training)의 중요성",
      content: "직원들의 보안 인식을 높여 사회공학 공격 등 인적 취약점을 줄이는 교육 프로그램입니다.",
      tags: ["Security Awareness", "Training", "Human Factor"],
      image: "https://upload.wikimedia.org/wikipedia/commons/thumb/a/a4/Security_Awareness_Icon.svg/320px-Security_Awareness_Icon.svg.png"
    }
  ];

  const searchInput = document.getElementById('search-input');
  const suggestionsList = document.getElementById('suggestions');
  const resultsContainer = document.getElementById('results');

  function detectMaliciousInput(text) {
    const pattern = /<script>|<\/script>|alert\s*\(/i;
    return pattern.test(text);
  }

  // 자동완성 보여주기
  function showSuggestions(value) {
    suggestionsList.innerHTML = '';
    if (!value) return;

    const filtered = keywords.filter(k => k.toLowerCase().includes(value.toLowerCase()));
    filtered.forEach(item => {
      const li = document.createElement('li');
      li.textContent = item;
      li.onclick = () => {
        searchInput.value = item;
        suggestionsList.innerHTML = '';
        performSearch(item);
      };
      suggestionsList.appendChild(li);
    });
  }

  // 검색어 하이라이트
  function highlightText(text, query) {
    const regex = new RegExp(`(${query.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')})`, 'gi');
    return text.replace(regex, '<span style="background-color:yellow;">$1</span>');
  }

  // 검색 수행
  function performSearch(query) {
    resultsContainer.innerHTML = '';
    suggestionsList.innerHTML = '';

    if (!query) return;

    if (detectMaliciousInput(query)) {
      resultsContainer.innerHTML = `<p style="color:red;">⚠️ 위험한 검색어가 포함되어 있습니다. 입력을 수정해주세요.</p>`;
      return;
    }

    const lowerQuery = query.trim().toLowerCase();

    const matchedArticles = securityArticles.filter(article => {
      return (
        article.title.toLowerCase().includes(lowerQuery) ||
        article.content.toLowerCase().includes(lowerQuery) ||
        article.tags.some(tag => tag.toLowerCase().includes(lowerQuery))
      );
    });

    if (matchedArticles.length === 0) {
      resultsContainer.innerHTML = `<p>검색 결과가 없습니다.</p>`;
      return;
    }

    matchedArticles.forEach(article => {
      const div = document.createElement('div');
      div.className = 'result-item';
      div.innerHTML = `
        <h3>${highlightText(article.title, query)}</h3>
        <img src="${article.image}" alt="${article.title}" style="max-width:100%; height:auto; border-radius: 6px; margin-bottom:10px;" />
        <p>${highlightText(article.content, query)}</p>
        <small>태그: ${article.tags.join(', ')}</small>
      `;
      resultsContainer.appendChild(div);
    });
  }

  // 이벤트 리스너 등록
  searchInput.addEventListener('input', e => {
    showSuggestions(e.target.value);
  });

  searchInput.addEventListener('keydown', e => {
    if (e.key === 'Enter') {
      performSearch(searchInput.value);
    }
  });
})();