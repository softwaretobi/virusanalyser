const TelegramBot = require('node-telegram-bot-api');
const fs = require('fs');
const axios = require('axios');
const FormData = require('form-data');
const puppeteer = require('puppeteer');


const botToken = 'ur bot token';
const virusTotalAPIKey = 'ur virus total api keys';




const bot = new TelegramBot(botToken, { polling: true });

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
        await page.goto(url, { waitUntil: 'networkidle2' });
        const screenshotPath = `./report_${this.sha1}.png`;
        await page.screenshot({ path: screenshotPath, fullPage: true });
        await browser.close();

        return screenshotPath;
    }

    calculateSecurityPercentage() {
        const totalScans = this.report.total || 0;
        const positiveScans = this.report.positives || 0;
        if (totalScans === 0) return 100; 
        return ((totalScans - positiveScans) / totalScans) * 100;
    }
}

bot.on('document', async (msg) => {
    const chatId = msg.chat.id;
    const fileId = msg.document.file_id;
    const filePath = `./${msg.document.file_name}`;

    bot.sendMessage(chatId, "Téléchargement en cours...");

    const fileLink = await bot.getFileLink(fileId);
    const response = await axios({
        method: 'GET',
        url: fileLink,
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

            const securityMessage = `Ton fichier "${msg.document.file_name}" a été scanné. Il est sécurisé à ${securityPercentage.toFixed(2)}%.`;
            bot.sendPhoto(chatId, screenshotPath);
            bot.sendMessage(chatId, securityMessage);
        } catch (error) {
            console.error('Error processing the file:', error);
            bot.sendMessage(chatId, "Erreur lors du traitement du fichier.");
        } finally {
            fs.unlinkSync(filePath); 
        }
    });

    writer.on('error', (err) => {
        console.error('Error writing file:', err);
        bot.sendMessage(chatId, "Erreur lors du téléchargement du fichier.");
    });
});
