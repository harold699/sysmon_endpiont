# sysmon_endpiont
Découvrez comment utiliser Sysmon pour surveiller et journaliser vos terminaux et environnements.
# Tâche 1 Introduction
Sysmon, un outil utilisé pour surveiller et consigner les événements sous Windows, est couramment utilisé par les entreprises dans le cadre de leurs solutions de surveillance et de journalisation. Sysmon, qui fait partie du package Windows Sysinternals, est similaire aux journaux d’événements Windows avec plus de détails et un contrôle granulaire.

Cette salle utilise une version modifiée des boîtes Blue et Ice, ainsi que les journaux Sysmon du labo du réseau Hololive.

Avant de terminer cette salle, nous vous recommandons de remplir la salle du journal des événements Windows. Il est également recommandé de compléter les salles Bleu et Glace pour comprendre les vulnérabilités présentes, mais il n’est pas nécessaire de continuer.

 # Tâche 2 Présentation de Sysmon
 Système Aperçu

D’après les documents Microsoft, « Le Moniteur système (Sysmon) est un service système Windows et un pilote de périphérique qui, une fois installé sur un système, reste résident lors des redémarrages du système pour surveiller et consigner l’activité du système dans le journal des événements Windows. Il fournit des informations détaillées sur les créations de processus, les connexions réseau et les modifications apportées au temps de création des fichiers. En collectant les événements qu’il génère à l’aide d’agents Windows Event Collection ou SIEM, puis en les analysant, vous pouvez identifier les activités malveillantes ou anormales et comprendre comment les intrus et les logiciels malveillants opèrent sur votre réseau.

Sysmon rassemble des journaux détaillés et de haute qualité, ainsi que des traçages d’événements qui aident à identifier les anomalies dans votre environnement. Sysmon est le plus souvent utilisé en conjonction avec le système de gestion des informations et des événements de sécurité (SIEM) ou d’autres solutions d’analyse de journaux qui agrègent, filtrent et visualisent les événements. Lorsqu’il est installé sur un point de terminaison, Sysmon démarre tôt dans le processus de démarrage de Windows. Dans un scénario idéal, les événements seraient transmis à un SIEM pour une analyse plus approfondie. Cependant, dans cette salle, nous allons nous concentrer sur Sysmon lui-même et afficher les événements sur le point de terminaison lui-même avec Windows Event Viewer.

Les événements au sein de Sysmon sont stockés dans Applications and Services Logs/Microsoft/Windows/Sysmon/Operational

Système Vue d’ensemble de la configuration

Sysmon a besoin d’un fichier de configuration pour indiquer au binaire comment analyser les événements qu’il reçoit. Vous pouvez créer votre propre configuration Sysmon ou télécharger une configuration. Voici un exemple de configuration de haute qualité qui fonctionne bien pour identifier les anomalies créées par SwiftOnSecurity : Sysmon-Config. Sysmon comprend 29 types différents d’ID d’événement, qui peuvent tous être utilisés dans la configuration pour spécifier comment les événements doivent être gérés et analysés. Ci-dessous, nous allons passer en revue quelques-uns des ID d’événement les plus importants et montrer des exemples de la façon dont ils sont utilisés dans les fichiers de configuration.

Lors de la création ou de la modification de fichiers de configuration, vous remarquerez que la majorité des règles de sysmon-config excluent les événements plutôt que de les inclure. Cela vous aidera à filtrer l’activité normale dans votre environnement, ce qui réduira le nombre d’événements et d’alertes que vous devrez auditer ou rechercher manuellement dans un SIEM. D’un autre côté, il existe des ensembles de règles comme la fourche sysmon-config ION-Storm qui adopte une approche plus proactive avec son ensemble de règles en utilisant beaucoup de règles d’inclusion. Vous devrez peut-être modifier les fichiers de configuration pour trouver l’approche que vous préférez. Les préférences de configuration varient en fonction de l’équipe SOC, alors préparez-vous à faire preuve de souplesse lors de la surveillance.

Remarque : Comme il y a tellement d’ID d’événement, Sysmon analyse. Nous ne passerons en revue que quelques-uns de ceux qui, selon nous, sont les plus importants à comprendre.

ID d’événement 1 : Création du processus

Cet événement recherchera tous les processus qui ont été créés. Vous pouvez l’utiliser pour rechercher des processus suspects connus ou des processus avec des fautes de frappe qui seraient considérés comme une anomalie. Cet événement utilisera les balises XML CommandLine et Image.

<RuleGroup name="" groupRelation="or">
	<ProcessCreate onmatch="exclude">
	 	<CommandLine condition="is">C:\Windows\system32\svchost.exe -k appmodel -p -s camsvc</CommandLine>
	</ProcessCreate>
</RuleGroup>

L’extrait de code ci-dessus spécifie l’ID d’événement à partir duquel extraire ainsi que la condition à rechercher. Dans ce cas, il s’agit d’exclure le processus svchost.exe des journaux d’événements.

ID d’événement 3 : Connexion réseau

L’événement de connexion réseau recherchera les événements qui se produisent à distance. Cela inclura les fichiers et les sources de binaires suspects ainsi que les ports ouverts. Cet événement utilisera les balises XML Image et DestinationPort.

<RuleGroup name="" groupRelation="or">
	<NetworkConnect onmatch="include">
	 	<Image condition="image">nmap.exe</Image>
	 	<DestinationPort name="Alert,Metasploit" condition="is">4444</DestinationPort>
	</NetworkConnect>
</RuleGroup>

L’extrait de code ci-dessus comprend deux façons d’identifier une activité de connexion réseau suspecte. La première méthode identifiera les fichiers transmis sur des ports ouverts. Dans ce cas, nous recherchons spécifiquement nmap.exe qui sera ensuite reflété dans les journaux d’événements. La deuxième méthode identifie les ports ouverts et plus particulièrement le port 4444 qui est couramment utilisé avec Metasploit. Si la condition est remplie, un événement sera créé et, idéalement, déclenchera une alerte pour que le SOC puisse approfondir l’enquête.

ID d’événement 7 : Image chargée

Cet événement recherchera les DLL chargées par les processus, ce qui est utile lors de la chasse aux attaques d’injection DLL et de détournement de DLL. Il est recommandé de faire preuve de prudence lors de l’utilisation de cet ID d’événement, car il entraîne une charge système élevée. Cet événement utilisera les balises XML Image, Signed, ImageLoaded et Signature.

<RuleGroup name="" groupRelation="or">
	<ImageLoad onmatch="include">
	 	<ImageLoaded condition="contains">\Temp\</ImageLoaded>
	</ImageLoad>
</RuleGroup>


L’extrait de code ci-dessus recherchera toutes les DLL qui ont été chargées dans le répertoire \Temp\. Si une DLL est chargée dans ce répertoire, elle peut être considérée comme une anomalie et doit faire l’objet d’une enquête plus approfondie.

ID d’événement 8 : CreateRemoteThread

L’ID d’événement CreateRemoteThread surveille les processus qui injectent du code dans d’autres processus. La fonction CreateRemoteThread est utilisée pour les tâches et les applications légitimes. Cependant, il pourrait être utilisé par des logiciels malveillants pour cacher une activité malveillante. Cet événement utilisera les balises XML SourceImage, TargetImage, StartAddress et StartFunction.

<RuleGroup name="" groupRelation="or">
	<CreateRemoteThread onmatch="include">
	 	<StartAddress name="Alert,Cobalt Strike" condition="end with">0B80</StartAddress>
	 	<SourceImage condition="contains">\</SourceImage>
	</CreateRemoteThread>
</RuleGroup>


L’extrait de code ci-dessus montre deux façons de surveiller CreateRemoteThread. La première méthode examinera l’adresse mémoire d’une condition de fin spécifique qui pourrait être un indicateur d’une balise Cobalt Strike. La deuxième méthode recherchera les processus injectés qui n’ont pas de processus parent. Cela doit être considéré comme une anomalie et nécessiter une enquête plus approfondie.

ID d’événement 11 : Fichier créé

Cet ID d’événement consigne les événements lors de la création ou de l’écrasement des fichiers sur le point de terminaison. Cela peut être utilisé pour identifier les noms de fichiers et les signatures des fichiers écrits sur le disque. Cet événement utilise des balises XML TargetFilename.

<RuleGroup name="" groupRelation="or">
	<FileCreate onmatch="include">
	 	<TargetFilename name="Alert,Ransomware" condition="contains">HELP_TO_SAVE_FILES</TargetFilename>
	</FileCreate>
</RuleGroup> 

L’extrait de code ci-dessus est un exemple de moniteur d’événements de ransomware. Ce n’est qu’un exemple de la variété de différentes façons dont vous pouvez utiliser l’ID d’événement 11.

ID d’événement 12 / 13 / 14 : Événement de registre

Cet événement recherche des changements ou des modifications dans le registre. Les activités malveillantes du registre peuvent inclure la persistance et l’utilisation abusive des informations d’identification. Cet événement utilise des balises XML TargetObject.

<RuleGroup name="" groupRelation="or">
	<RegistryEvent onmatch="include">
	 	<TargetObject name="T1484" condition="contains">Windows\System\Scripts</TargetObject>
	</RegistryEvent>
</RuleGroup>

L’extrait de code ci-dessus recherchera les objets de registre qui se trouvent dans le répertoire « Windows\System\Scripts », car il s’agit d’un répertoire commun permettant aux adversaires de placer des scripts pour établir la persistance.

ID d’événement 15 : FileCreateStreamHash

Cet événement recherchera tous les fichiers créés dans un autre flux de données. Il s’agit d’une technique couramment utilisée par les adversaires pour masquer les logiciels malveillants. Cet événement utilise des balises XML TargetFilename.

<RuleGroup name="" groupRelation="or">
	<FileCreateStreamHash onmatch="include">
	 	<TargetFilename condition="end with">.hta</TargetFilename>
	</FileCreateStreamHash>
</RuleGroup> 

L’extrait de code ci-dessus recherchera les fichiers avec le . HTA qui ont été placées dans un autre flux de données.

ID d’événement 22 : Événement DNS

Cet événement consigne toutes les requêtes et tous les événements DNS à des fins d’analyse. La façon la plus courante de gérer ces événements est d’exclure tous les domaines de confiance dont vous savez qu’ils seront très courants dans votre environnement. Une fois que vous vous êtes débarrassé du bruit, vous pouvez alors rechercher des anomalies DNS. Cet événement utilise des balises XML QueryName.

<RuleGroup name="" groupRelation="or">
	<DnsQuery onmatch="exclude">
	 	<QueryName condition="end with">.microsoft.com</QueryName>
	</DnsQuery>
</RuleGroup> 

L’extrait de code ci-dessus exclura tous les événements DNS avec la requête .microsoft.com. Cela vous débarrassera du bruit que vous voyez dans l’environnement.

Il existe une variété de méthodes et de balises que vous pouvez utiliser pour personnaliser vos fichiers de configuration. Nous utiliserons les fichiers de configuration ION-Storm et SwiftOnSecurity pour le reste de cette salle, mais n’hésitez pas à utiliser vos propres fichiers de configuration.

Répondez aux questions ci-dessous
Lisez ce qui précède et familiarisez-vous avec les ID d’événement Sysmon.
Aucune réponse n’est nécessaire

Bonne réponse

# Tâche 3 Installation et préparation du système
Installation de Sysmon

L’installation de Sysmon est assez simple et ne nécessite que le téléchargement du binaire depuis le site Web de Microsoft. Vous pouvez également télécharger tous les outils Sysinternals avec une commande PowerShell si vous le souhaitez plutôt que de récupérer un seul fichier binaire. Il est également recommandé d’utiliser un fichier de configuration Sysmon avec Sysmon pour obtenir un suivi d’événements plus détaillé et de haute qualité. À titre d’exemple de fichier de configuration, nous utiliserons le fichier sysmon-config du dépôt GitHub de SwiftOnSecurity.

Vous pouvez trouver le binaire Sysmon sur le site Web Microsoft Sysinternals. Vous pouvez également télécharger la suite Microsoft Sysinternal ou utiliser la commande ci-dessous pour exécuter un module PowerShell, télécharger et installer tous les outils Sysinternals.

Commande PowerShell : Download-SysInternalsTools C:\Sysinternals

Pour utiliser pleinement Sysmon, vous devrez également télécharger une configuration Sysmon ou créer votre propre configuration. Nous vous suggérons de télécharger le sysmon-config de SwiftOnSecurity. Une configuration Sysmon permettra un contrôle plus granulaire des journaux ainsi qu’un suivi d’événements plus détaillé. Dans cette salle, nous utiliserons à la fois le fichier de configuration SwiftOnSecurity et le fichier de configuration ION-Storm.

Démarrage du système

Pour démarrer Sysmon, vous devez ouvrir un nouveau PowerShell ou une nouvelle invite de commande en tant qu’administrateur. Ensuite, exécutez la commande ci-dessous, il exécutera le binaire Sysmon, acceptera le contrat de licence de l’utilisateur final et utilisera le fichier de configuration SwiftOnSecurity.

Commande utilisée : Sysmon.exe -accepteula -i ..\Configurations\swift.xml
<img width="1486" height="488" alt="image" src="https://github.com/user-attachments/assets/c6210731-4b26-4bbd-82f6-43b8005c8f03" />


Système
Installation
C:\Users\THM-Analyst\Desktop\Tools\Sysmon>Sysmon.exe -accepteula -i ..\Configurations\swift.xml

System Monitor v12.03 - System activity monitor
Copyright (C) 2014-2020 Mark Russinovich and Thomas Garnier
Sysinternals - www.sysinternals.com

Loading configuration file with schema version 4.10
Sysmon schema version: 4.40
Configuration file validated.
Sysmon installed.
SysmonDrv installed.
Starting SysmonDrv.
SysmonDrv started.
Starting Sysmon..
Maintenant que Sysmon a démarré avec le fichier de configuration que nous voulons utiliser, nous pouvons consulter l’Observateur d’événements pour surveiller les événements. Le journal des événements se trouve sous Applications and Services Logs/Microsoft/Windows/Sysmon/Operational

Remarque : À tout moment, vous pouvez modifier le fichier de configuration utilisé en désinstallant ou en mettant à jour la configuration actuelle et en la remplaçant par un nouveau fichier de configuration. Pour plus d’informations, consultez le menu d’aide de Sysmon.

S’il est correctement installé, votre journal des événements doit ressembler à ce qui suit :
<img width="1255" height="305" alt="image" src="https://github.com/user-attachments/assets/3f2324d9-1e9b-469d-a49e-15aa35e23563" />


Visionneuse de journaux d’événements Windows affichant 10 journaux de Sysmon

Pour cette salle, nous avons déjà créé pour vous un environnement avec Sysmon et des fichiers de configuration. Déployez et utilisez cette machine pour le reste de cette pièce.

IP de la machine : MACHINE_IP

Utilisateur: THM-Analyst

Passer: 5TgcYzF84tcBSuL1Boa%dzcvf

La machine démarrera dans une vue en écran partagé. Si la machine virtuelle n’est pas visible, utilisez le bouton bleu Afficher la vue partagée en haut à droite de la page.

Répondez aux questions ci-dessous
Déployez la machine et démarrez Sysmon.
Aucune réponse n’est nécessaire

Bonne réponse
Présentation des activités malveillantes

Étant donné que la plupart de l’activité normale ou du « bruit » observé sur un réseau est exclue ou filtrée avec Sysmon, nous sommes en mesure de nous concentrer sur des événements significatifs. Cela nous permet d’identifier et d’enquêter rapidement sur les activités suspectes. Lorsque vous surveillez activement un réseau, vous voudrez utiliser plusieurs détections et techniques simultanément dans le but d’identifier les menaces. Pour cette salle, nous allons seulement voir à quoi ressembleront les journaux suspects avec les deux configurations Sysmon et comment optimiser votre chasse en utilisant uniquement Sysmon. Nous verrons comment détecter les balises de ransomware, de persistance, de Mimikatz, de Metasploit et de commande et de contrôle (C2). De toute évidence, il ne s’agit que d’une petite poignée d’événements qui pourraient être déclenchés dans un environnement. La méthodologie sera en grande partie la même pour les autres menaces. Il s’agit vraiment d’utiliser un fichier de configuration suffisant et efficace, car il peut faire une grande partie du travail pour vous.

Vous pouvez télécharger les journaux d’événements utilisés pour cette tâche ou les ouvrir à partir du répertoire Practice sur l’ordinateur fourni.

Système « Meilleures pratiques »

Sysmon offre une plate-forme assez ouverte et configurable à votre disposition. D’une manière générale, il existe quelques bonnes pratiques que vous pouvez mettre en œuvre pour vous assurer de fonctionner efficacement et de ne manquer aucune menace potentielle. Quelques bonnes pratiques courantes sont décrites et expliquées ci-dessous.

Exclure > inclure
Lors de la création de règles pour votre fichier de configuration Sysmon, il est généralement préférable de donner la priorité à l’exclusion d’événements plutôt qu’à l’inclusion d’événements. Cela vous évite de manquer accidentellement des événements cruciaux et de ne voir que les événements qui comptent le plus.

L’interface de ligne de commande vous donne plus de contrôle
Comme c’est souvent le cas avec la plupart des applications, l’interface de ligne de commande vous offre le plus de contrôle et de filtrage, ce qui permet un contrôle granulaire supplémentaire. Vous pouvez utiliser l’un ou l’autre pour accéder aux journaux et les filtrer. Au fur et à mesure que vous intégrez Sysmon dans votre SIEM ou d’autres solutions de détection, ces outils deviendront moins utilisés et nécessaires. Get-WinEventwevutil.exe

Connaître votre environnement avant la mise en œuvre
Il est important de connaître votre environnement lors de la mise en œuvre d’une plateforme ou d’un outil. Vous devez avoir une bonne compréhension du réseau ou de l’environnement dans lequel vous travaillez pour bien comprendre ce qui est normal et ce qui est suspect afin d’élaborer efficacement vos règles.

Filtrage d’événements avec l’Observateur d’événements

L’Observateur d’événements n’est peut-être pas le meilleur outil pour filtrer les événements, et il offre un contrôle limité sur les journaux. Le filtre principal que vous utiliserez avec l’Observateur d’événements consiste à filtrer les mots-clés et . Vous pouvez également choisir de filtrer en écrivant XML, mais il s’agit d’un processus fastidieux qui ne s’adapte pas bien.EventID

Pour ouvrir le menu de filtre, sélectionnez dans le menu Actions. Filter Current Log
<img width="373" height="357" alt="image" src="https://github.com/user-attachments/assets/15d4a5f3-f604-4163-a550-66d2166960c3" />


Capture d’écran du menu d’actions de la visionneuse du journal des événements Windows

Si vous avez réussi à ouvrir le menu des filtres, il devrait ressembler au menu ci-dessous.
<img width="678" height="681" alt="image" src="https://github.com/user-attachments/assets/59d99465-ad77-41f2-9fcb-a5247fa75d9b" />

capture d’écran du menu de filtre de la visionneuse du journal des événements Windows

À partir de ce menu, nous pouvons ajouter tous les filtres ou catégories que nous voulons.

Filtrage des événements avec PowerShell

Pour afficher et filtrer les événements avec PowerShell, nous allons utiliser avec les requêtes. Nous pouvons utiliser toutes les requêtes XPath qui se trouvent dans la vue XML des événements. Nous utiliserons pour afficher les événements une fois filtrés. La ligne de commande est généralement utilisée sur l’interface graphique de l’observateur d’événements, car elle permet un contrôle et un filtrage plus granulaires, ce qui n’est pas le cas de l’interface graphique. Pour plus d’informations sur l’utilisation et consultez la salle Journal des événements Windows.Get-WinEventXPathwevutil.exeGet-WinEventwevutil.exe

Pour cette salle, nous ne passerons en revue que quelques filtres de base, car la salle du journal des événements Windows couvre déjà largement ce sujet.

Filtrer par ID d’événement : */System/EventID=<ID>

Filtrer par attribut/nom XML : */EventData/Data[@Name="<XML Attribute/Name>"]

Filtrer par données d’événement : */EventData/Data=<Data>

Nous pouvons combiner ces filtres avec divers attributs et données pour tirer le meilleur parti de nos journaux. Regardez ci-dessous un exemple d’utilisation pour rechercher des connexions réseau provenant du port 4444.Get-WinEvent

Get-WinEvent -Path <Path to Log> -FilterXPath '*/System/EventID=3 and */EventData/Data[@Name="DestinationPort"] and */EventData/Data=4444'
<img width="1498" height="342" alt="image" src="https://github.com/user-attachments/assets/2320ee35-b046-42a0-a457-e9b45afe4633" />


Filtrage des événements
PS C:\Users\THM-Analyst> Get-WinEvent -Path C:\Users\THM-Analyst\Desktop\Scenarios\Practice\Hunting_Metasploit.evtx -FilterXPath '*/System/EventID=3 and */EventData/Data[@Name="DestinationPort"] and */EventData/Data=4444'


   ProviderName: Microsoft-Windows-Sysmon

TimeCreated                     Id LevelDisplayName Message
-----------                     -- ---------------- -------
1/5/2021 2:21:32 AM              3 Information      Network connection detected:...
Répondez aux questions ci-dessous
Lisez ce qui précède et entraînez-vous à filtrer les événements.
Aucune réponse n’est nécessaire

Bonne réponse
Combien y a-t-il d’événements d’ID d’événement 3 dans C :\Users\THM-Analyst\Desktop\Scenarios\Practice\Filtering.evtx ?

__,___

Envoyer
Quelle est l’heure UTC du premier événement réseau dans le même fichier journal ? Notez que l’heure UTC n’est affichée que dans l’onglet « Détails ».

__________ __:__:__.___

Envoyer
