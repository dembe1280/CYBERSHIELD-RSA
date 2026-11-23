const root = document.documentElement;
const themeToggle = document.getElementById("themeToggle");
const themeIcon = document.getElementById("themeIcon");
const themeLabel = document.getElementById("themeLabel");
const savedTheme = localStorage.getItem("cybershield-theme");
if (savedTheme) root.dataset.theme = savedTheme;

function updateThemeButton() {
  const dark = root.dataset.theme === "dark";
  themeIcon.textContent = dark ? "☀" : "☾";
  themeLabel.textContent = dark ? "Light mode" : "Dark mode";
}
updateThemeButton();
themeToggle.addEventListener("click", () => {
  root.dataset.theme = root.dataset.theme === "dark" ? "light" : "dark";
  localStorage.setItem("cybershield-theme", root.dataset.theme);
  updateThemeButton();
});

const menuToggle = document.getElementById("menuToggle");
const mainNav = document.getElementById("mainNav");
menuToggle.addEventListener("click", () => mainNav.classList.toggle("open"));
mainNav.querySelectorAll("a").forEach(link => link.addEventListener("click", () => mainNav.classList.remove("open")));

const tools = {
  url: {title:"URL scanner", description:"Paste a link you'd like to review.", label:"Suspicious link", placeholder:"https://example.com", hint:"Paste the full link. Do not open it first."},
  message: {title:"Scam message checker", description:"Share a suspicious SMS or WhatsApp message for review.", label:"Message text", placeholder:"Paste the message here…", hint:"Remove personal details, account numbers and OTPs first."},
  email: {title:"Phishing email checker", description:"Review the wording and sender details of a suspicious email.", label:"Email content", placeholder:"Paste the email text and sender address…", hint:"Do not paste attachments, passwords or private account information."},
  phone: {title:"Phone number checker", description:"Check a number against community reports when that service is connected.", label:"Phone number", placeholder:"+27 …", hint:"A number being unfamiliar does not mean it is a scam."},
  password: {title:"Password strength check", description:"Assess a password locally in your browser. It will not be sent to a server.", label:"Password to assess", placeholder:"Enter a password to assess", hint:"For this prototype, the password check is not yet implemented. Never enter a password you currently use."}
};
const workspace = document.getElementById("workspace");
const scanInput = document.getElementById("scanInput");
let selectedTool = "url";
document.querySelectorAll(".tool-card").forEach(card => {
  card.addEventListener("click", () => {
    selectedTool = card.dataset.tool;
    const tool = tools[selectedTool];
    document.getElementById("workspaceTitle").textContent = tool.title;
    document.getElementById("workspaceDescription").textContent = tool.description;
    document.getElementById("inputLabel").textContent = tool.label;
    scanInput.placeholder = tool.placeholder;
    document.getElementById("privacyHint").textContent = tool.hint;
    scanInput.value = "";
    workspace.hidden = false;
    workspace.scrollIntoView({behavior:"smooth", block:"center"});
  });
});
document.getElementById("closeWorkspace").addEventListener("click", () => workspace.hidden = true);
document.getElementById("scanForm").addEventListener("submit", event => {
  event.preventDefault();
  const notice = document.getElementById("prototypeNotice");
  notice.innerHTML = "<strong>Live scanning is not connected yet</strong><p>Your input has not been sent anywhere and no safety verdict has been generated. The next development step is to connect this tool to the backend and trusted threat-intelligence services.</p>";
  notice.scrollIntoView({behavior:"smooth", block:"nearest"});
});
document.getElementById("year").textContent = new Date().getFullYear();
