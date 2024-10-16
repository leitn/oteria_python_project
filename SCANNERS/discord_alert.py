#discord_alert.py

import requests


DISCORD_WEBHOOK_DDOS = 'https://discord.com/api/webhooks/1296092623265726545/R7Baj9qBY-3O5km8_HVJ934HhmNmMi_Wj5zGLuzUtdhTEldOheYbUXOKh2RuDC6HXsDD'
DISCORD_WEBHOOK_BRUTE_FORCE = 'https://discord.com/api/webhooks/1296094525055438920/i2qtcOeLi9TNlHqz5e_TJr-y4uZd30vsOruxP63LNwSS0eMHpoL4uTyD4upruE4SPFxh'
DISCORD_WEBHOOK_PSCAN ='https://discord.com/api/webhooks/1296094641732452515/irHY_BZqH0PEW4E4oosfjvX7newp_envrNshoO32qcl34dgTjW3mWHIu-GL6PaZf6gGB'

def chose_global(chan_select):
	if chan_select == 1:
		d_chan = DISCORD_WEBHOOK_DDOS
	elif chan_select == 2:
		d_chan = DISCORD_WEBHOOK_BRUTE_FORCE
	elif chan_select == 3:
		d_chan = DISCORD_WEBHOOK_PSCAN
	else:
		d_chan = DISCORD_WEBHOOK_DDOS #CHANGER 
	return (d_chan)

def send_discord_alert(message, channel_select):
	'''Poste une alerte sur le serveur discord choisi.
	   Le lien du discord est hardcodé dans la 
	   variable globale "DISCORD_WEBHOOK_DDOS"
	   L'envoie de l'alerte se fait via la méthode post 
	   de la librairie requests de Python3
	'''
	
	d_channel = chose_global(channel_select)
		
	data = {
        "content": message,  # Le message d'alerte
        "Alerteur": "Alerte Réseau",  # Nom d'utilisateur du bot qui enverra l'alerte
    }
	response = requests.post(d_channel, json=data) #requête POST contenant le message à l'URL du Chan Discord. Le message est formaté en JSON.
	if response.status_code == 204:  # Code de succès pour Discord
		print("Alerte envoyée sur Discord.")
	else:
		print(f"Erreur lors de l'envoi de l'alerte : {response.status_code}")