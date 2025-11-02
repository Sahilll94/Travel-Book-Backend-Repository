const express = require('express');
const { exec } = require('child_process');
const app = express();
const PORT = 9000;

app.use(express.json());

app.post('/webhook', (req, res) => {
    console.log('Webhook received!');
    exec('cd /home/ubuntu/Travel-Book-Backend && git pull origin main && pm2 restart all', (err, stdout, stderr) => {
        if (err) {
            console.error(err);
            return res.status(500).send('Deployment failed');
        }
        console.log(stdout);
        res.status(200).send('Deployed!');
    });
});

app.listen(PORT, () => {
    console.log(`Webhook server running on port ${PORT}`);
});
