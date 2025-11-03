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


##Filtrage des événements
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

73,591

<img width="1255" height="105" alt="image" src="https://github.com/user-attachments/assets/240d9b81-249c-4690-8029-cc106bc424cc" />


Envoyer
Quelle est l’heure UTC du premier événement réseau dans le même fichier journal ? Notez que l’heure UTC n’est affichée que dans l’onglet « Détails ».

2021-01-06 01:35:50.464

Envoyer
<img width="1257" height="99" alt="image" src="https://github.com/user-attachments/assets/c695b000-d051-4f33-bfe7-b6c8e001c16b" />

#Tâche 5 : Chasse au Metasploit

Metasploit est un framework d’exploitation couramment utilisé pour les tests d’intrusion et les opérations d’équipe rouge. Metasploit peut être utilisé pour exécuter facilement des exploits sur une machine et se reconnecter à un shell meterpreter. Nous allons chasser la coquille meterpreter elle-même et les fonctionnalités qu’elle utilise. Pour commencer la chasse, nous allons rechercher des connexions réseau provenant de ports suspects tels que et . Par défaut, Metasploit utilise le port 4444. S’il existe une connexion à une adresse IP connue ou inconnue, elle doit être examinée. Pour démarrer une enquête, vous pouvez consulter les captures de paquets à partir de la date du journal pour commencer à rechercher des informations supplémentaires sur l’adversaire. Nous pouvons également rechercher des processus suspects créés. Cette méthode de chasse peut être appliquée à d’autres balises RAT et C2.44445555

Pour plus d’informations sur cette technique et les outils utilisés, consultez le logiciel MITRE ATT&CK.

Pour plus d’informations sur la façon dont les logiciels malveillants et les charges utiles interagissent avec le réseau, consultez la feuille de calcul des ports courants des logiciels malveillants. Ce point sera abordé plus en détail dans la tâche Chasse aux logiciels malveillants.

Vous pouvez télécharger les journaux d’événements utilisés dans cette salle à partir de cette tâche ou les ouvrir dans le dossier Practice de l’ordinateur fourni.

Connexions au réseau de chasse

Nous allons d’abord examiner une configuration modifiée d’Ion-Security pour détecter la création de nouvelles connexions réseau. L’extrait de code ci-dessous utilisera l’ID d’événement 3 avec le port de destination pour identifier les connexions actives, en particulier les connexions sur le port et . 44445555

<RuleGroup name="" groupRelation="or">
	<NetworkConnect onmatch="include">
		<DestinationPort condition="is">4444</DestinationPort>
		<DestinationPort condition="is">5555</DestinationPort>
	</NetworkConnect>
</RuleGroup>
<img width="1275" height="191" alt="image" src="https://github.com/user-attachments/assets/9be2864a-8265-4ad6-aa76-d6dcb454a95a" />


Ouvrez-le dans l’Observateur d’événements pour afficher une charge utile Metasploit de base déposée sur la machine.C:\Users\THM-Analyst\Desktop\Scenarios\Practice\Hunting_Metasploit.evtx

Screenshot of Windows event log viewer showing details of a suspicious tcp log
<img width="537" height="485" alt="image" src="https://github.com/user-attachments/assets/ecba9a6b-33e5-44fc-916c-6596a39401fc" />

Une fois que nous avons identifié l’événement, il peut nous donner des informations importantes que nous pouvons utiliser pour une enquête plus approfondie, comme le et .ProcessIDImage

Chasse aux ports ouverts avec PowerShell

Pour rechercher des ports ouverts avec PowerShell, nous allons utiliser le module PowerShell avec des requêtes. Nous pouvons utiliser les mêmes requêtes XPath que celles que nous avons utilisées dans la règle pour filtrer les événements à partir de . La ligne de commande est généralement utilisée sur l’interface graphique de l’Observateur d’événements, car elle peut permettre un contrôle et un filtrage plus précis que l’interface graphique n’offre pas. Pour plus d’informations sur l’utilisation de XPath et de la ligne de commande pour l’affichage des événements, consultez la salle du journal des événements Windows de Heavenraiza.Get-WinEventXPathNetworkConnectDestinationPort

Get-WinEvent -Path <Path to Log> -FilterXPath '*/System/EventID=3 and */EventData/Data[@Name="DestinationPort"] and */EventData/Data=4444'

##Chasse Metasploit
PS C:\Users\THM-Analyst> Get-WinEvent -Path C:\Users\THM-Analyst\Desktop\Scenarios\Practice\Hunting_Metasploit.evtx -FilterXPath '*/System/EventID=3 and */EventData/Data[@Name="DestinationPort"] and */EventData/Data=4444'


   ProviderName: Microsoft-Windows-Sysmon

TimeCreated                     Id LevelDisplayName Message
-----------                     -- ---------------- -------
1/5/2021 2:21:32 AM              3 Information      Network connection detected:...
<img width="1254" height="318" alt="image" src="https://github.com/user-attachments/assets/1eca980a-1ba0-48c2-b3d8-54233e442bcd" />

Nous pouvons décomposer cette commande par ses filtres pour voir exactement ce qu’elle fait. Il s’agit d’abord d’un filtrage par l’ID d’événement 3 qui est l’ID de connexion réseau. Il filtre ensuite par le nom de données dans ce cas DestinationPort ainsi que par le port spécifique que nous voulons filtrer. Nous pouvons ajuster cette syntaxe en même temps que nos événements pour obtenir exactement les données que nous voulons en retour.

Répondez aux questions ci-dessous
Lisez ce qui précède et entraînez-vous à chasser Metasploit avec le fichier d’événements fourni.
Aucune réponse n’est nécessaire

Bonne réponse

##Tâche 6 Détection de Mimikatz

Télécharger les fichiers de tâches
Détection de Mimikatz Vue d’ensemble

Mimikatz est bien connu et couramment utilisé pour vider les informations d’identification de la mémoire ainsi que d’autres activités de post-exploitation Windows. Mimikatz est principalement connu pour le dumping de LSASS. Nous pouvons rechercher le fichier créé, l’exécution du fichier à partir d’un processus élevé, la création d’un thread distant et les processus créés par Mimikatz. L’antivirus détecte généralement Mimikatz car la signature est très connue, mais il est toujours possible pour les acteurs de la menace d’obscurcir ou d’utiliser des droppers pour obtenir le fichier sur l’appareil. Pour cette chasse, nous utiliserons un fichier de configuration personnalisé pour minimiser le bruit du réseau et nous concentrer sur la chasse.

Pour plus d’informations sur cette technique et les logiciels utilisés, consultez MITRE ATTACK T1055 et S0002.

Vous pouvez télécharger les journaux d’événements utilisés dans cette salle à partir de cette tâche ou les ouvrir dans le dossier Practice de l’ordinateur fourni.

##Détection de la création de fichiers

La première méthode de chasse à Mimikatz consiste simplement à rechercher des fichiers créés avec le nom Mimikatz. Il s’agit d’une technique simple, mais qui peut vous permettre de trouver tout ce qui aurait pu contourner l’AV. La plupart du temps, lorsqu’il s’agit d’une menace avancée, vous aurez besoin de techniques de chasse plus avancées, comme la recherche du comportement LSASS, mais cette technique peut toujours être utile.

Il s’agit d’un moyen très simple de détecter l’activité de Mimikatz qui a contourné l’antivirus ou d’autres mesures de détection. Mais la plupart du temps, il est préférable d’utiliser d’autres techniques comme la chasse au comportement spécifique au LSASS. Vous trouverez ci-dessous un extrait d’une configuration pour aider à la chasse à Mimikatz.

<RuleGroup name="" groupRelation="or">
	<FileCreate onmatch="include">
		<TargetFileName condition="contains">mimikatz</TargetFileName>
	</FileCreate>
</RuleGroup>


Comme cette méthode ne sera pas couramment utilisée pour rechercher des anomalies, nous n’examinerons pas les journaux d’événements pour cette technique spécifique.

##Chasse au comportement anormal du LSASS

Nous pouvons utiliser l’ID d’événement ProcessAccess pour rechercher un comportement LSASS anormal. Cet événement, ainsi que le LSASS, montreraient un abus potentiel du LSASS, qui renvoie généralement à Mimikatz, un autre type d’outil de dumping d’identifiants. Regardez ci-dessous pour plus de détails sur la chasse avec ces techniques.

Si LSASS est accédé par un processus autre que svchost.exe il doit être considéré comme un comportement suspect et doit faire l’objet d’une enquête plus approfondie, pour faciliter la recherche d’événements suspects, vous pouvez utiliser un filtre pour rechercher uniquement des processus autres que svchost.exe. Sysmon nous fournira plus de détails pour nous aider à mener l’enquête, tels que le chemin d’accès au fichier d’où provient le processus. Pour faciliter les détections, nous utiliserons un fichier de configuration personnalisé. Vous trouverez ci-dessous un extrait de la configuration qui vous aidera dans la chasse.

<RuleGroup name="" groupRelation="or">
	<ProcessAccess onmatch="include">
	       <TargetImage condition="image">lsass.exe</TargetImage>
	</ProcessAccess>
</RuleGroup>
<img width="538" height="147" alt="image" src="https://github.com/user-attachments/assets/fce35541-39fa-4da0-8c8c-2745b9a01dae" />

Ouvrez dans l’Observateur d’événements pour afficher une attaque utilisant une version obfusquée de Mimikatz pour vider les informations d’identification de la mémoire.C:\Users\THM-Analyst\Desktop\Scenarios\Practice\Hunting_LSASS.evtx

screenshot of Windows event log viewer showing details of a mimikatz log
<img width="961" height="429" alt="image" src="https://github.com/user-attachments/assets/5882b61e-9984-4923-a3e1-28c340c4cd72" />

Nous voyons l’événement auquel le processus de Mimikatz a eu accès, mais nous voyons aussi beaucoup d’événements svchost.exe ? Nous pouvons modifier notre configuration pour exclure les événements dont l’événement provient de svhost.exe. Vous trouverez ci-dessous une règle de configuration modifiée pour réduire le bruit présent dans les journaux d’événements.SourceImage

<RuleGroup name="" groupRelation="or">
	<ProcessAccess onmatch="exclude">
		<SourceImage condition="image">svchost.exe</SourceImage>
	</ProcessAccess>
	<ProcessAccess onmatch="include">
		<TargetImage condition="image">lsass.exe</TargetImage>
	</ProcessAccess>
</RuleGroup>
 <img width="522" height="235" alt="image" src="https://github.com/user-attachments/assets/53e03d20-e0e9-4efd-8451-dfe80ed7bc2a" />


En modifiant le fichier de configuration pour inclure cette exception, nous avons considérablement réduit nos événements et pouvons nous concentrer uniquement sur les anomalies. Cette technique peut être utilisée dans Sysmon et les événements pour réduire le « bruit » dans les journaux.

##Détection du comportement LSASS avec PowerShell

Pour détecter un comportement LSASS anormal avec PowerShell, nous utiliserons à nouveau le module PowerShell avec des requêtes. Nous pouvons utiliser les mêmes requêtes XPath que celles utilisées dans la règle pour filtrer les autres processus à partir de . Si nous l’utilisons avec un fichier de configuration bien construit avec une règle précise, il fera une grande partie du travail pour nous et nous n’aurons besoin de filtrer qu’une petite quantité.Get-WinEventXPathTargetImage

Get-WinEvent -Path <Path to Log> -FilterXPath '*/System/EventID=10 and */EventData/Data[@Name="TargetImage"] and */EventData/Data="C:\Windows\system32\lsass.exe"'

##Chasse à Mimikatz

PS C:\Users\THM-Analyst> Get-WinEvent -Path C:\Users\THM-Analyst\Desktop\Scenarios\Practice\Hunting_Mimikatz.evtx -FilterXPath '*/System/EventID=10 and */EventData/Data[@Name="TargetImage"] and */EventData/Data="C:\Windows\system32\lsass.exe"'

   ProviderName: Microsoft-Windows-Sysmon

TimeCreated                     Id LevelDisplayName Message
-----------                     -- ---------------- -------
1/5/2021 3:22:52 AM             10 Information      Process accessed:...
<img width="1257" height="362" alt="image" src="https://github.com/user-attachments/assets/ea1cac37-4967-4066-bb75-bb969715ac7e" />

Répondez aux questions ci-dessous
Lisez ce qui précède et entraînez-vous à détecter Mimikatz avec l’evtx fourni.

Aucune réponse n’est nécessaire

Bonne réponse
## Tâche 7 Chasse aux logiciels malveillants

Télécharger les fichiers de tâches
##Présentation de la chasse aux logiciels malveillants

Les logiciels malveillants se présentent sous de nombreuses formes et variantes avec des objectifs finaux différents. Les deux types de logiciels malveillants sur lesquels nous nous concentrerons sont les RAT et les portes dérobées. Les RAT ou chevaux de Troie d’accès à distance sont utilisés de la même manière que n’importe quelle autre charge utile pour obtenir un accès à distance à une machine. Les RAT sont généralement associés à d’autres techniques d’évasion antivirus et de détection qui les différencient des autres charges utiles telles que MSFVenom. Un RAT utilise généralement également un modèle client-serveur et est livré avec une interface pour faciliter l’administration des utilisateurs. Des exemples de TAR sont et . Pour aider à détecter et à chasser les logiciels malveillants, nous devrons d’abord identifier les logiciels malveillants que nous voulons chasser ou détecter et identifier les moyens de modifier les fichiers de configuration, c’est ce qu’on appelle la chasse basée sur des hypothèses. Il existe bien sûr une pléthore d’autres façons de détecter et d’enregistrer les logiciels malveillants, mais nous ne couvrirons que la méthode de base de détection des ports de connexion à dos ouvert. XeexeQuasar

Pour plus d’informations sur cette technique et des exemples de logiciels malveillants, consultez le logiciel MITRE ATT&CK.

Vous pouvez télécharger les journaux d’événements utilisés dans cette salle à partir de cette tâche ou les ouvrir dans le dossier Practice de l’ordinateur fourni.

##Chasse aux rats et serveurs C2

La première technique que nous utiliserons pour chasser les logiciels malveillants est un processus similaire à la chasse au Metasploit. Nous pouvons parcourir et créer un fichier de configuration pour rechercher et détecter les ports suspects ouverts sur le point de terminaison. En utilisant des ports suspects connus à inclure dans nos journaux, nous pouvons ajouter à notre méthodologie de chasse dans laquelle nous pouvons utiliser les journaux pour identifier les adversaires sur notre réseau, puis utiliser des captures de paquets ou d’autres stratégies de détection pour poursuivre l’enquête. L’extrait de code ci-dessous provient du fichier de configuration Ion-Storm qui alertera lorsque des ports spécifiques aiment et excluent des connexions réseau courantes comme OneDrive, en excluant les événements, nous voyons toujours tout ce que nous voulons sans rien manquer et réduire le bruit. 10341604

Lorsque vous utilisez des fichiers de configuration dans un environnement de production, vous devez être prudent et comprendre exactement ce qui se passe dans le fichier de configuration, par exemple le fichier de configuration Ion-Storm exclut le port 53 en tant qu’événement. Les attaquants et les adversaires ont commencé à utiliser le port 53 dans le cadre de leurs logiciels malveillants/charges utiles, qui ne seraient pas détectés si vous utilisiez aveuglément ce fichier de configuration tel quel.

Pour plus d’informations sur les ports sur lesquels ce fichier de configuration est alerté, consultez cette feuille de calcul.

<RuleGroup name="" groupRelation="or">
	<NetworkConnect onmatch="include">
		<DestinationPort condition="is">1034</DestinationPort>
		<DestinationPort condition="is">1604</DestinationPort>
	</NetworkConnect>
	<NetworkConnect onmatch="exclude">
		<Image condition="image">OneDrive.exe</Image>
	</NetworkConnect>
</RuleGroup>
<img width="489" height="258" alt="image" src="https://github.com/user-attachments/assets/396a8c69-c339-4aa2-958e-994db48f13bf" />


Ouvrez dans l’Observateur d’événements pour voir un rat en direct déposé sur le serveur.C:\Users\THM-Analyst\Desktop\Scenarios\Practice\Hunting_Rats.evtx

screenshot of Windows event log viewer showing details of a RAT log
<img width="551" height="512" alt="image" src="https://github.com/user-attachments/assets/bce1704c-e8ab-4c97-a34f-45c97ca7d85a" />

Dans l’exemple ci-dessus, nous détectons un RAT personnalisé qui fonctionne sur le port 8080. C’est un exemple parfait de la raison pour laquelle vous devez être prudent lorsque vous excluez des événements afin de ne pas manquer une activité malveillante potentielle.

#Recherche de ports de back-connect communs avec PowerShell

Tout comme les sections précédentes, lors de l’utilisation de PowerShell, nous utiliserons à nouveau le module PowerShell avec des requêtes pour filtrer nos événements et obtenir un contrôle granulaire sur nos journaux. Nous devrons filtrer sur l’ID de l’événement et l’attribut data. Si vous utilisez un bon fichier de configuration avec un ensemble fiable de règles, il fera la majorité du travail et le filtrage selon ce que vous voulez devrait être facile.Get-WinEventXPathNetworkConnectDestinationPort

Get-WinEvent -Path <Path to Log> -FilterXPath '*/System/EventID=3 and */EventData/Data[@Name="DestinationPort"] and */EventData/Data=<Port>'
<img width="1242" height="411" alt="image" src="https://github.com/user-attachments/assets/9995e981-d5a6-43a6-a0c1-f38b7bd7562b" />

Connexions de chasse

PS C:\Users\THM-Analyst> Get-WinEvent -Path C:\Users\THM-Analyst\Desktop\Scenarios\Practice\Hunting_Rats.evtx -FilterXPath '*/System/EventID=3 and */EventData/Data[@Name="DestinationPort"] and */EventData/Data=8080'

   ProviderName: Microsoft-Windows-Sysmon

TimeCreated                     Id LevelDisplayName Message
-----------                     -- ---------------- -------
1/5/2021 4:44:35 AM              3 Information      Network connection detected:...
1/5/2021 4:44:31 AM              3 Information      Network connection detected:...
1/5/2021 4:44:27 AM              3 Information      Network connection detected:...
1/5/2021 4:44:24 AM              3 Information      Network connection detected:...
1/5/2021 4:44:20 AM              3 Information      Network connection detected:...
Répondez aux questions ci-dessous
Lisez ce qui précède et entraînez-vous à chasser les rats et les serveurs C2 avec des ports de connexion arrière.

---
## Tâche 8 Chasse persistante

Télécharger les fichiers de tâches
#Persistence Overview

Persistence is used by attackers to maintain access to a machine once it is compromised. There is a multitude of ways for an attacker to gain persistence on a machine. We will be focusing on registry modification as well as startup scripts. We can hunt persistence with Sysmon by looking for File Creation events as well as Registry Modification events. The SwiftOnSecurity configuration file does a good job of specifically targeting persistence and techniques used. You can also filter by the Rule Names in order to get past the network noise and focus on anomalies within the event logs. 

Vous pouvez télécharger les journaux d’événements utilisés dans cette salle à partir de cette tâche ou les ouvrir dans le dossier Practice de l’ordinateur fourni.

#Hunting Startup Persistence

We will first be looking at the SwiftOnSecurity detections for a file being placed in the  or directories. Below is a snippet of the config that will aid in event tracing for this technique. For more information about this technique check out MITRE ATT&CK T1547.\Startup\\Start Menu

<RuleGroup name="" groupRelation="or">
	<FileCreate onmatch="include">
		<TargetFilename name="T1023" condition="contains">\Start Menu</TargetFilename>
		<TargetFilename name="T1165" condition="contains">\Startup\</TargetFilename>
	</FileCreate>
</RuleGroup>
<img width="670" height="187" alt="image" src="https://github.com/user-attachments/assets/87906711-99d4-408e-9d1d-7a8f082199c7" />


Open   in Event Viewer to view a live attack on the machine that involves persistence by adding a malicious EXE into the Startup folder.C:\Users\THM-Analyst\Desktop\Scenarios\Practice\T1023.evtx
<img width="930" height="260" alt="image" src="https://github.com/user-attachments/assets/a936e53a-fde5-4143-9a90-4f02effdc39d" />



When looking at the Event Viewer we see that persist.exe was placed in the Startup folder. Threat Actors will almost never make it this obvious but any changes to the Start Menu should be investigated. You can adjust the configuration file to be more granular and create alerts past just the File Created tag. We can also filter by the Rule Name T1023


<img width="1183" height="579" alt="image" src="https://github.com/user-attachments/assets/bd9ef314-da9e-41da-a574-548b9e6a1d9d" />



Once you have identified that a suspicious binary or application has been placed in a startup location you can begin an investigation on the directory.

#Hunting Registry Key Persistence

We will again be looking at another SwiftOnSecurity detection this time for a registry modification that adjusts that places a script inside and other registry locations. For more information about this technique check out MITRE ATT&CK T1112.CurrentVersion\Windows\Run

<RuleGroup name="" groupRelation="or">
	<RegistryEvent onmatch="include">
		<TargetObject name="T1060,RunKey" condition="contains">CurrentVersion\Run</TargetObject>
		<TargetObject name="T1484" condition="contains">Group Policy\Scripts</TargetObject>
		<TargetObject name="T1060" condition="contains">CurrentVersion\Windows\Run</TargetObject>
	</RegistryEvent>
</RuleGroup>
<img width="741" height="208" alt="image" src="https://github.com/user-attachments/assets/2af4aa92-e78b-47e9-bfc4-22a803cf556c" />


Open in Event Viewer to view an attack where the registry was modified to gain persistence.C:\Users\THM-Analyst\Desktop\Scenarios\Practice\T1060.evtx

<img width="706" height="266" alt="image" src="https://github.com/user-attachments/assets/1a8531af-6e42-4b4b-8af8-367f8cabcf0e" />


When looking at the event logs we see that the registry was modified and malicious.exe was added to  We also see that the exe can be found at HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Persistence%windir%\System32\malicious.exe

Just like the startup technique, we can filter by the to make finding the anomaly easier. RuleName T1060

If we wanted to investigate this anomaly we would need to look at the registry as well as the file location itself. Below is the registry area where the malicious registry key was placed.


<img width="957" height="187" alt="image" src="https://github.com/user-attachments/assets/c54c9961-a98d-4e62-9598-56fe9a0270f9" />

Répondez aux questions ci-dessous
Read the above and practice hunting persistence techniques.
Aucune réponse n’est nécessaire

Bonne réponse
---

##Tâche 9 Détection des techniques d’évasion

Télécharger les fichiers de tâches
##Aperçu des techniques d’évasion

Il existe un certain nombre de techniques d’évasion utilisées par les auteurs de logiciels malveillants pour échapper à la fois aux antivirus et aux détections. Quelques exemples de techniques d’évasion sont les flux de données alternatifs, les injections, le masquage, l’emballage/compression, la recompilation, l’obfuscation, les techniques anti-retournement. Dans cette tâche, nous nous concentrerons sur les flux de données alternatifs et les injections. Les flux de données alternatifs sont utilisés par les logiciels malveillants pour cacher leurs fichiers à l’inspection normale en enregistrant le fichier dans un flux différent de . Sysmon est livré avec un ID d’événement pour détecter les flux nouvellement créés et consultés, ce qui nous permet de détecter et de chasser rapidement les logiciels malveillants qui utilisent ADS. Il en existe de nombreux types de techniques d’injection : détournement de fil, injection PE, injection DLL, etc. Dans cette salle, nous nous concentrerons sur l’injection de DLL et les DLL de porte dérobée. Pour ce faire, il suffit de prendre une DLL déjà utilisée par une application et d’écraser ou d’inclure votre code malveillant dans la DLL.$DATA

Pour plus d’informations sur cette technique, consultez les modèles MITRE ATT&CK T1564 et T1055.

Vous pouvez télécharger les journaux d’événements utilisés dans cette salle à partir de cette tâche ou les ouvrir dans le dossier Practice de l’ordinateur fourni.

#Chasse aux flux de données alternatifs

La première technique que nous allons examiner consiste à masquer des fichiers à l’aide de flux de données alternatifs à l’aide de l’ID d’événement 15. L’ID d’événement 15 hache et consigne tous les flux NTFS inclus dans le fichier de configuration Sysmon. Cela nous permettra de chasser les logiciels malveillants qui échappent aux détections à l’aide d’ADS. Pour faciliter la chasse à l’ADS, nous utiliserons le fichier de configuration SwiftOnSecurity Sysmon. L’extrait de code ci-dessous recherchera les fichiers dans le dossier et ainsi que dans l’extension and.TempDownloads.hta.bat

<RuleGroup name="" groupRelation="or">
<FileCreateStreamHash onmatch="include">
<TargetFilename condition="contains">Downloads</TargetFilename>
<TargetFilename condition="contains">Temp\7z</TargetFilename>
<TargetFilename condition="ends with">.hta</TargetFilename>
<TargetFilename condition="ends with">.bat</TargetFilename>
</FileCreateStreamHash>
</RuleGroup>
<img width="510" height="233" alt="image" src="https://github.com/user-attachments/assets/d053e701-f540-4cbe-b44c-1300451b76ff" />

Ouvrir dans l’Observateur d’événements pour afficher les fichiers masqués à l’aide d’un autre flux de données.C:\Users\THM-Analyst\Desktop\Scenarios\Practice\Hunting_ADS.evtx



 <img width="658" height="300" alt="image" src="https://github.com/user-attachments/assets/d18dbdcf-8a2d-4997-bcfd-2cbcfce9d781" />


Liste des flux de données
C:\\Users\\THM-Threat>dir /r
 Volume in drive C has no label.
 Volume Serial Number is C0C4-7EC1

 Directory of C:\\Users\\THM-Threat

10/23/2022  02:56 AM    <DIR>          .
10/23/2022  02:56 AM    <DIR>          ..
01/02/2021  12:43 AM    <DIR>          3D Objects
01/02/2021  12:43 AM    <DIR>          Contacts
01/05/2021  11:53 PM    <DIR>          Desktop
01/02/2021  12:43 AM    <DIR>          Documents
01/10/2021  12:11 AM    <DIR>          Downloads
01/02/2021  12:43 AM    <DIR>          Favorites
01/02/2021  12:43 AM    <DIR>          Links
01/02/2021  12:43 AM    <DIR>          Music
10/23/2022  02:56 AM                 0 not_malicious.txt
                                    13 not_malicious.txt:malicious.txt:$DATA 
Comme vous pouvez le voir, l’événement nous montrera l’emplacement du nom du fichier ainsi que le contenu du fichier, ce qui sera utile si une enquête est nécessaire.

#Détection des threads distants

Les adversaires utilisent également couramment des threads distants pour échapper aux détections en combinaison avec d’autres techniques. Les threads distants sont créés à l’aide de l’API Windows et sont accessibles à l’aide de et . Ceci est utilisé dans plusieurs techniques d’évasion, notamment l’injection de DLL, le détournement de fil et l’évidement de processus. Nous utiliserons l’ID d’événement Sysmon 8 du fichier de configuration SwiftOnSecurity. L’extrait de code ci-dessous de la règle exclura les threads distants courants sans inclure d’attributs spécifiques, ce qui permet d’obtenir une règle d’événement plus ouverte et plus précise. CreateRemoteThreadOpenThreadResumeThread

<RuleGroup name="" groupRelation="or">
<CreateRemoteThread onmatch="exclude">
<SourceImage condition="is">C:\Windows\system32\svchost.exe</SourceImage>
<TargetImage condition="is">C:\Program Files (x86)\Google\Chrome\Application\chrome.exe</TargetImage>
</CreateRemoteThread>
</RuleGroup>
<img width="800" height="187" alt="image" src="https://github.com/user-attachments/assets/7fe385c7-60c0-4d6c-8072-bf271416f447" />


Ouvrez dans l’Observateur d’événements pour observer une attaque Process Hollowing qui abuse du processus notepad.exe. C:\Users\THM-Analyst\Desktop\Scenarios\Practice\Detecting_RemoteThreads.evtx

screenshot of Windows event log viewer showing details of a powershell session executed from notepad
<img width="655" height="369" alt="image" src="https://github.com/user-attachments/assets/0c40e8c3-3344-40dc-a4ca-4bf1797a61eb" />

Comme vous pouvez le voir dans l’image powershell ci-dessus.exe crée un fil de discussion distant et accède à notepad.exe. Il s’agit évidemment d’un PoC et pourrait en théorie exécuter n’importe quel autre type d’exécutable ou de DLL. La technique spécifique utilisée dans cet exemple s’appelle l’injection PE réfléchissante.

Détection des techniques d’évasion avec PowerShell

Nous avons déjà passé en revue la majorité de la syntaxe requise pour utiliser PowerShell avec des événements. Comme pour les tâches précédentes, nous utiliserons avec le pour filtrer et rechercher des fichiers qui utilisent un autre flux de données ou créent un fil de discussion distant. Dans les deux cas, nous n’aurons qu’à filtrer par le car la règle utilisée dans le fichier de configuration fait déjà la majorité du gros du travail. Get-WinEventXPathEventID

# Détection de la création de threads distants

Syntaxe: Get-WinEvent -Path <Path to Log> -FilterXPath '*/System/EventID=8'

Détection des threads distants

PS C:\Users\THM-Analyst> Get-WinEvent -Path C:\Users\THM-Analyst\Desktop\Scenarios\Practice\Detecting_RemoteThreads.evtx -FilterXPath '*/System/EventID=8'
**<img width="1254" height="422" alt="image" src="https://github.com/user-attachments/assets/281a4113-81ee-4314-abb0-358eb4815b6f" />**
   ProviderName: Microsoft-Windows-Sysmon

TimeCreated                     Id LevelDisplayName Message
-----------                     -- ---------------- -------
7/3/2019 8:39:30 PM              8 Information      CreateRemoteThread detected:...
7/3/2019 8:39:30 PM              8 Information      CreateRemoteThread detected:...
7/3/2019 8:39:30 PM              8 Information      CreateRemoteThread detected:...
7/3/2019 8:39:30 PM              8 Information      CreateRemoteThread detected:...
7/3/2019 8:39:30 PM              8 Information      CreateRemoteThread detected:...
Répondez aux questions ci-dessous
Lisez ce qui précède et pratiquez les techniques de détection de l’évasion
Aucune réponse n’est nécessaire

Bonne réponse

---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

# 🕵️‍♂️ Tâche 10 — Investigations pratiques

Les fichiers d’événements utilisés dans cette tâche proviennent des référentiels Github EVTX-ATTACK-SAMPLES et SysmonResources.

Vous pouvez télécharger les journaux d’événements utilisés dans cette salle à partir de cette tâche ou les ouvrir dans le dossier Investigations sur l’ordinateur fourni.

Enquête 1 - UGH, BILL THAT’S WRONG USB !

Dans le cadre de cette enquête, votre équipe a reçu des rapports indiquant qu’un fichier malveillant a été déposé sur un hôte par une clé USB malveillante. Ils ont extrait les journaux suspects et vous ont chargé de mener l’enquête pour cela.

Les journaux se trouvent dans .C:\Users\THM-Analyst\Desktop\Scenarios\Investigations\Investigation-1.evtx

Enquête 2 - Ce n’est pas un fichier HTML ?

Un autre fichier suspect est apparu dans vos journaux et a réussi à exécuter du code se masquant sous la forme d’un fichier HTML, échappant ainsi à vos détections antivirus. Ouvrez les journaux et examinez le fichier suspect.

Les journaux se trouvent dans .C:\Users\THM-Analyst\Desktop\Scenarios\Investigations\Investigation-2.evtx

Enquête 3.1 - 3.2 - Où est le videur quand on a besoin de lui

Votre équipe vous a informé que l’adversaire a réussi à configurer la persistance sur vos points de terminaison alors qu’il continue de se déplacer sur votre réseau. Découvrez comment l’adversaire a réussi à obtenir de la persistance à l’aide des journaux fournis.

Les journaux se trouvent dans C:\Users\THM-Analyst\Desktop\Scenarios\Investigations\Investigation-3.1.evtx

et.C:\Users\THM-Analyst\Desktop\Scenarios\Investigations\Investigation-3.2.evtx

Enquête 4 - Maman, regarde ! J’ai créé un botnet !

Au fur et à mesure que l’adversaire a pris pied sur votre réseau, il a été porté à votre attention qu’il aurait peut-être été en mesure d’établir des communications C2 sur certains des terminaux. Collectez les journaux et poursuivez votre enquête.

Les journaux se trouvent dans .C:\Users\THM-Analyst\Desktop\Scenarios\Investigations\Investigation-4.evtx

## 🔍 Enquête 1 — UGH, BILL THAT’S WRONG USB !

**Fichier :** `Investigation-1.evtx`
Pour identifier la clé de registre, il faut examiner l’événement 13 – “Registry value set”, puis observer le champ TargetObject, qui indique précisément la clé modifiée ou créée.
**Question 1 :** Quelle est la clé de registre complète du périphérique USB qui appelle svchost.exe ?
**Réponse :**
`HKLM\System\CurrentControlSet\Enum\WpdBusEnumRoot\UMB\2&37c186b&0&STORAGE#VOLUME#_??_USBSTOR#DISK&VEN_SANDISK&PROD_U3_CRUZER_MICRO&REV_8.01#4054910EF19005B3&0#\FriendlyName`

<img width="1273" height="102" alt="image" src="https://github.com/user-attachments/assets/be58c09a-19df-4854-84f2-8360ca103bd4" />


<img width="1031" height="145" alt="image" src="https://github.com/user-attachments/assets/c9bd8369-d603-42a4-98b8-ae4e93d0a450" />


**Question 2 :** Quel est le nom de l’appareil lorsqu’il est appelé par RawAccessRead ?

Événement 9 — Object create
Cet événement signale la création d’un nouvel objet de registre dans Windows.
Autrement dit, il indique qu’une nouvelle clé de registre a été créée dans le système.
C’est utile pour retracer l’installation d’un périphérique ou d’un programme, car cela montre le moment précis où une clé est apparue dans le registre.

**Réponse :**
`\Device\HarddiskVolume3`

<img width="1257" height="104" alt="image" src="https://github.com/user-attachments/assets/7171b048-3a8d-4f62-bb05-a21e992d2d2f" />


<img width="648" height="366" alt="image" src="https://github.com/user-attachments/assets/a645f9e5-8fdb-4208-95a5-a7fb5a30987a" />

**Question 3 :** Quel est le premier exe exécuté par le processus ?
Pour identifier le premier exécutable lancé par un processus, il faut examiner les événements de type “Process creation” (ID 1) dans les journaux Windows.
Le champ ParentCommandLine indique le chemin complet de l’exécutable (.exe) qui a été exécuté.
**Réponse :**
`rundll32.exe`

<img width="1269" height="99" alt="image" src="https://github.com/user-attachments/assets/1f4d4f75-287d-43ac-bc5e-ec74320ceb64" />


<img width="984" height="527" alt="image" src="https://github.com/user-attachments/assets/13ba18f8-2e12-42b6-af6c-c2649c651d22" />


---

## 💻 Enquête 2 — Ce n’est pas un fichier HTML ?

**Fichier :** `Investigation-2.evtx`

**Question 1 :** Quel est le chemin complet de la charge utile ?
Pour trouver le chemin complet de la charge utile, il faut examiner les événements de type “CommandLine” (ID 1) ou 
Le champ contient le chemin complet du fichier exécuté ou déposé sur le système.
Ces champs sont essentiels car ils permettent d’identifier l’emplacement exact du fichier malveillant (la charge utile), ce qui aide à retracer son origine et à évaluer son impact sur l’hôte.
**Réponse :**
`C:\Users\IEUser\AppData\Local\Microsoft\Windows\Temporary Internet Files\Content.IE5\S97WTYG7\update.hta`


<img width="1273" height="111" alt="image" src="https://github.com/user-attachments/assets/d105d1d0-9599-4eec-b201-a6d1dfe6161f" />


<img width="973" height="430" alt="image" src="https://github.com/user-attachments/assets/80860918-1178-4eae-909c-858580b56309" />


**Question 2 :** Quel est le chemin d’accès complet du fichier que la charge utile s’est masquée ?
Pour trouver le chemin complet de la charge utile, il faut examiner les événements de type “  ParentCommandLine ” (ID 1) 
**Réponse :**
`C:\Users\IEUser\Downloads\update.html`

<img width="1253" height="119" alt="image" src="https://github.com/user-attachments/assets/08f4edf9-a9f4-442c-a29e-7b82b2d4e30d" />


<img width="912" height="480" alt="image" src="https://github.com/user-attachments/assets/a2c06244-5d55-45ec-971e-b41a6d193eeb" />

**Question 3 :** Quel binaire signé a exécuté la charge utile ?
Pour trouver le chemin complet de la charge utile, il faut examiner les événements de type “ Image” (ID 3) 
L’événement 3 (Network connection) est utilisé pour surveiller les connexions réseau établies par les processus.
Il enregistre les détails sur les communications sortantes et entrantes, notamment :

le processus à l’origine de la connexion (Image),

l’adresse IP distante (DestinationIp),

le port distant (DestinationPort),

et le protocole utilisé.
**Réponse :**
`C:\Windows\System32\mshta.exe`

<img width="1274" height="96" alt="image" src="https://github.com/user-attachments/assets/be4fcd0b-eb1f-4d08-b2a7-f307cb7e6a82" />



**Question 4 :** Quelle est l’adresse IP de l’adversaire ?
**Réponse :**
`10.0.2.18`

<img width="1265" height="111" alt="image" src="https://github.com/user-attachments/assets/30d87590-2365-488a-9510-99c0bf54e8f4" />



**Question 5 :** Quel port de connexion arrière est utilisé ?
**Réponse :**
`4443`

<img width="1267" height="121" alt="image" src="https://github.com/user-attachments/assets/bb8e5cbd-f2a4-4bf2-9c2d-834a9f1e06fb" />


<img width="1009" height="580" alt="image" src="https://github.com/user-attachments/assets/68bd8396-ef86-4a0b-9451-7abdd77fece0" />


---

## 🧩 Enquête 3.1 — Où est le videur quand on a besoin de lui

**Fichier :** `Investigation-3.1.evtx`

L’événement 3 (Network connection)

**Question 1 :** Quelle est l’adresse IP de l’adversaire présumé ?
**Réponse :**
`172.30.1.253`



**Question 2 :** Quel est le nom d’hôte du point de terminaison affecté ?
**Réponse :**
`DESKTOP-O153T4R`

<img width="1281" height="110" alt="image" src="https://github.com/user-attachments/assets/3c2ab208-a3a3-4711-b274-72ec533fa8aa" />


**Question 3 :** Quel est le nom d’hôte du serveur C2 ?
**Réponse :**
`empirec2`

<img width="1282" height="101" alt="image" src="https://github.com/user-attachments/assets/fb97181a-b74b-486c-ae66-e144b4d19a59" />


<img width="986" height="576" alt="image" src="https://github.com/user-attachments/assets/a0ccb9ae-97cd-4165-b673-a05f67f1cab2" />


**Question 4 :** Où dans le registre la charge utile était-elle stockée ?
**Réponse :**
`HKLM\SOFTWARE\Microsoft\Network\debug`

<img width="1271" height="114" alt="image" src="https://github.com/user-attachments/assets/a9d62b7b-93e8-4319-88c7-676c33d14da7" />


<img width="1024" height="494" alt="image" src="https://github.com/user-attachments/assets/d69ef1a5-1f35-42b6-a46c-b6feb12e88d0" />




**Question 5 :** Quel code PowerShell a été utilisé pour lancer la charge utile ?
**Réponse :**

```powershell
"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -c "$x=$((gp HKLM:Software\Microsoft\Network debug).debug);start -Win Hidden -A \"-enc $x\" powershell";exit;
```

<img width="1274" height="115" alt="image" src="https://github.com/user-attachments/assets/b346babf-c0a4-4da7-8e19-fc14c53c8bee" />


<img width="1011" height="521" alt="image" src="https://github.com/user-attachments/assets/c4d747af-3445-40b4-8e36-65cc096a28d5" />



---

## 🧠 Enquête 3.2 — Tâche planifiée suspecte

**Fichier :** `Investigation-3.2.evtx`

**Question 1 :** Quelle est la propriété intellectuelle (adresse IP de l’adversaire) ?
**Réponse :**
`172.168.103.188`

<img width="1270" height="109" alt="image" src="https://github.com/user-attachments/assets/4e468dab-0e47-4221-a03e-6efc74d6bba9" />


**Question 2 :** Quel est le chemin complet de l’emplacement de la charge utile ?
**Réponse :**
`c:\users\q\AppData:blah.txt`

<img width="1038" height="529" alt="image" src="https://github.com/user-attachments/assets/1c6b834b-fec6-446c-8a91-82519ea4897e" />

<img width="1262" height="106" alt="image" src="https://github.com/user-attachments/assets/2f93d2e6-9cc6-465f-927a-ba8cf1ae2169" />


**Question 3 :** Quelle a été la commande complète utilisée pour créer la tâche planifiée ?
**Réponse :**

```bash
"C:\WINDOWS\system32\schtasks.exe" /Create /F /SC DAILY /ST 09:00 /TN Updater /TR "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NonI -W hidden -c \"IEX ([Text.Encoding]::UNICODE.GetString([Convert]::FromBase64String($(cmd /c ''more < c:\users\q\AppData:blah.txt'''))))\""
```

<img width="1266" height="105" alt="image" src="https://github.com/user-attachments/assets/9e8604a3-7cae-4e9b-a828-e22c51f2e90e" />


<img width="1133" height="426" alt="image" src="https://github.com/user-attachments/assets/db433f62-d956-4acf-9c89-8d163915dbb8" />

**Question 4 :** À quel processus les schtasks.exe suspects ont-ils accédé ?
💡 L’événement 10 (ProcessAccess) est utilisé pour surveiller quand un processus tente d’accéder à un autre processus sur le système.

Cet événement indique qu’un programme a demandé un accès mémoire ou une interaction directe avec un autre processus (par exemple, lecture, écriture ou injection de code).

Les champs importants incluent :

SourceImage → le processus qui fait l’accès ;

TargetImage → le processus ciblé (souvent sensible comme lsass.exe ou explorer.exe) ;

GrantedAccess → le type d’accès obtenu.

🔍 Cet événement est crucial pour détecter les tentatives de vol de mots de passe ou d’injection de code, notamment lors d’attaques visant lsass.exe, typiques des dump de crédentiels.

**Réponse :**
`lsass.exe`

<img width="1266" height="116" alt="image" src="https://github.com/user-attachments/assets/66b5663c-6dd7-461a-bbdc-930a13e11179" />


<img width="865" height="456" alt="image" src="https://github.com/user-attachments/assets/5696878d-147f-4c3e-8292-7d1f5af1bc55" />


---

## 🌐 Enquête 4 — Maman, regarde ! J’ai créé un botnet !

**Fichier :** `Investigation-4.evtx`

**Question 1 :** Quelle est l’adresse IP de l’adversaire ?
**Réponse :**
`172.30.1.253`

<img width="1256" height="110" alt="image" src="https://github.com/user-attachments/assets/a2e6a196-00ce-446d-89ef-9eab881bca20" />


**Question 2 :** Sur quel port l’adversaire opère-t-il ?
**Réponse :**
`80`

<img width="1271" height="110" alt="image" src="https://github.com/user-attachments/assets/d56aadcb-7c60-4fa8-b32b-fa22759b8286" />


**Question 3 :** Quel C2 l’adversaire utilise-t-il ?
**Réponse :**
`Empire`

<img width="1243" height="111" alt="image" src="https://github.com/user-attachments/assets/c30fcdd1-d631-4f6d-b140-0296e8313499" />


<img width="1215" height="507" alt="image" src="https://github.com/user-attachments/assets/661908d0-124b-4bf3-b12a-a46eab6e9774" />



simo harold  steve




