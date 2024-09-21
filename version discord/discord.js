const { Client, GatewayIntentBits, EmbedBuilder } = require('discord.js'); // Importation correcte pour discord.js v14+
const fs = require('fs');
const axios = require('axios');
const FormData = require('form-data');
const puppeteer = require('puppeteer');

const botToken = 'ur discord token ';
const virusTotalAPIKey = 'ur virus total api keys ';




// Client Discord avec les intents nécessaires
const client = new Client({
    intents: [
        53608447
    ]
});

class VirusTotal {
    constructor(apiKey) {
        this.apiKey = apiKey;
        this.sha1 = '';
        this.verbose = '';
        this.report = {};
    }

    async scanFile(filePath) {
        console.log(`Scanning file: ${filePath}`);
        const url = 'https://www.virustotal.com/vtapi/v2/file/scan';
        const form = new FormData();
        const fileStream = fs.createReadStream(filePath);

        form.append('file', fileStream);
        form.append('apikey', this.apiKey);

        const response = await axios.post(url, form, {
            headers: {
                ...form.getHeaders(),
            },
        });

        this.sha1 = response.data.sha1;
        this.verbose = response.data.verbose_msg;
        console.log(`Scan completed. SHA1: ${this.sha1}`);
    }

    async getReport() {
        console.log(`Fetching report for SHA1: ${this.sha1}`);
        const url = `https://www.virustotal.com/vtapi/v2/file/report?apikey=${this.apiKey}&resource=${this.sha1}`;
        const response = await axios.get(url);
        this.report = response.data;
        console.log('Report fetched:', this.report);
    }

    async captureReport() {
        const url = `https://www.virustotal.com/gui/file/${this.sha1}`;
        console.log(`Capturing report screenshot from: ${url}`);

        const browser = await puppeteer.launch();
        const page = await browser.newPage();

        // Ajuster le viewport pour capturer avec un zoom
        await page.setViewport({
            width: 1280,
            height: 720,
            deviceScaleFactor: 2 // Zoom pour un meilleur focus
        });

        await page.goto(url, { waitUntil: 'networkidle2' });

        // Ajuster le zoom de la page à 150%
        await page.evaluate(() => {
            document.body.style.zoom = '1.5';
        });

        // Capturer la capture d'écran zoomée
        const screenshotPath = `./report_${this.sha1}.png`;
        await page.screenshot({ path: screenshotPath, fullPage: false }); // Désactiver fullPage pour un zoom concentré

        await browser.close();
        return screenshotPath;
    }

    calculateSecurityPercentage() {
        const totalScans = this.report.total || 0;
        const positiveScans = this.report.positives || 0;
        if (totalScans === 0) return 100; // Pas de scan, considéré comme sûr
        return ((totalScans - positiveScans) / totalScans) * 100;
    }
}

client.on('ready', () => {
    console.log(`Logged in as ${client.user.tag}`);
});

client.on('messageCreate', async (message) => {
    if (message.author.bot) return; // Ignorer les messages des autres bots

    if (message.attachments.size > 0) {
        const attachment = message.attachments.first();
        const filePath = `./${attachment.name}`;

        // Vérifier si l'utilisateur a mentionné le bot
        if (message.mentions.has(client.user)) {
            const embed = new EmbedBuilder()
                .setColor('#000000') // Couleur noire
                .setTitle('Téléchargement en cours...')
                .setDescription(`Le fichier "${attachment.name}" est en cours de téléchargement et d'analyse.`);

            message.reply({ embeds: [embed] });

            // Télécharger le fichier joint
            const response = await axios({
                method: 'GET',
                url: attachment.url,
                responseType: 'stream',
            });

            const writer = fs.createWriteStream(filePath);
            response.data.pipe(writer);

            writer.on('finish', async () => {
                console.log(`File saved: ${filePath}`);
                try {
                    const vt = new VirusTotal(virusTotalAPIKey);
                    await vt.scanFile(filePath);
                    await vt.getReport();
                    const screenshotPath = await vt.captureReport();
                    const securityPercentage = vt.calculateSecurityPercentage();

                    // Créer un embed avec les informations du scan
                    const resultEmbed = new EmbedBuilder()
                        .setColor('#000000') // Couleur noire
                        .setTitle('Résultat du scan VirusTotal')
                        .setDescription(`Ton fichier "${attachment.name}" a été scanné. Il est sécurisé à ${securityPercentage.toFixed(2)}%.`)
                        .setImage(`attachment://${screenshotPath}`); // Ajouter l'image capturée dans l'embed

                    // Envoyer l'embed avec l'image de la capture d'écran
                    message.reply({ 
                        embeds: [resultEmbed], 
                        files: [{ attachment: screenshotPath, name: `report_${vt.sha1}.png` }] 
                    });
                } catch (error) {
                    console.error('Error processing the file:', error);
                    message.reply("Erreur lors du traitement du fichier.");
                } finally {
                    fs.unlinkSync(filePath); // Supprimer le fichier après traitement
                }
            });

            writer.on('error', (err) => {
                console.error('Error writing file:', err);
                message.reply("Erreur lors du téléchargement du fichier.");
            });
        }
    }
});

client.login(botToken);
