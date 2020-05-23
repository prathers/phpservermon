<?php

/**
 * PHP Server Monitor
 * Monitor your servers and websites.
 *
 * This file is part of PHP Server Monitor.
 * PHP Server Monitor is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * PHP Server Monitor is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with PHP Server Monitor.  If not, see <http://www.gnu.org/licenses/>.
 *
 * @package     phpservermon
 * @author      nerdalertdk, prathers <preben@rather.dk>
 * @copyright   Copyright (c) 2008-2017 Pepijn Over <pep@mailbox.org>
 * @license     http://www.gnu.org/licenses/gpl.txt GNU GPL v3
 * @version     Release: @package_version@
 * @link        http://www.phpservermonitor.org/
 **/

$sm_lang = array(
    'name' => 'Dansk - Danish',
    'locale' => array(
        '0' => 'da_DK.UTF-8',
        '1' => 'da_DK',
        '2' => 'danish',
        '3' => 'danish-dk',
    ),
    'system' => array(
        'title' => 'Server Monitor',
        'install' => 'Installér',
        'action' => 'Handling',
        'save' => 'Gem',
        'edit' => 'Redigér',
        'delete' => 'Slet',
        'date' => 'Dato',
        'message' => 'Besked',
        'yes' => 'Ja',
        'no' => 'Nej',
        'insert' => 'Indsæt',
        'add_new' => 'Tilføj ny',
        'update_available' => 'En ny version ({version}) er tilgængelig på <a
 href="https://github.com/phpservermon/phpservermon/releases/latest" target="_blank"
 rel="noopener">http://www.phpservermonitor.org</a>.',
        'back_to_top' => 'Til toppen',
        'go_back' => 'Tilbage',
        'ok' => 'OK',
        'bad' => 'dårlig',
        'cancel' => 'Annulér',
        'none' => 'Ingen',
        'activate' => 'Aktivér',
        'short_day_format' => '%B %e',
        'long_day_format' => '%B %e, %Y',
        'yesterday_format' => 'I går %k:%M',
        'other_day_format' => '%A %k:%M',
        'never' => 'Aldrig',
        'hours_ago' => '%d timer siden',
        'an_hour_ago' => 'omkring en time siden',
        'minutes_ago' => '%d minutter siden',
        'a_minute_ago' => 'omkring et minut siden',
        'seconds_ago' => '%d sekunder siden',
        'a_second_ago' => 'et sekund siden',
        'seconds' => 'sekunder',
        'year' => 'år',
        'years' => 'år',
        'month' => 'måned',
        'months' => 'måneder',
        'day' => 'dag',
        'days' => 'dage',
        'hour' => 'time',
        'hours' => 'timers',
        'minute' => 'minut',
        'minutes' => 'minutter',
        'millisecond' => 'millisekund',
        'milliseconds' => 'millisekunder',
        'current' => 'aktuel',
        'settings' => 'Indstillinger',
        'search' => 'Søg',
    ),
    'menu' => array(
        'config' => 'Indstillinger',
        'server' => 'Servere',
        'server_log' => 'Log',
        'server_status' => 'Status',
        'server_update' => 'Opdatér',
        'user' => 'Brugere',
        'help' => 'Hjælp',
    ),
    'users' => array(
        'user' => 'Bruger',
        'name' => 'Navn',
        'user_name' => 'Brugernavn',
        'password' => 'Adgangskode',
        'password_repeat' => 'Adgangskode igen',
        'password_leave_blank' => 'Udfyldes hvis du vil skifte adgangskode',
        'level' => 'Niveau',
        'level_10' => 'Administrator',
        'level_20' => 'Bruger',
        'level_description' => '<b>Administratorer</b> har fuld adgang: De kan styre servere, brugere og
 indstillinger.<br><b>Brugere</b> kan kun se og opdatere servere som er de har adgang
 til.',
        'mobile' => 'Mobil',
        'email' => 'E-mail',
        'pushover' => 'Pushover',
        'pushover_description' => 'Pushover er en service der gør det let at modtage real-time notifikationer. Se <a
 href="https://pushover.net/" target="_blank">deres website</a> for mere information.',
        'pushover_key' => 'Pushover nøgle',
        'pushover_device' => 'Pushover enhed',
        'pushover_device_description' => 'Navnet på enheden som beskeden skal sendes til. Lad denne være tom hvis alle skal modtage beskeden.',
        'telegram' => 'Telegram',
        'telegram_description' => '<a href="https://telegram.org/" target="_blank">Telegram</a> en en chat app som
 gør det nemt at modtage notifikationer i realtid. Besøg <a
 href="http://docs.phpservermonitor.org/" target="_blank">documentation</a> for yderligere
 info og en installationsvejledning.',
        'telegram_chat_id' => 'Telegram chat id',
        'telegram_chat_id_description' => 'Denne besked vil blive sendt til den tilsvarende chat.',
        'telegram_get_chat_id' => 'Klik her for at få den chat id',
        'activate_telegram' => 'Aktivér Telegram notifikationer',
        'activate_telegram_description' => 'Tillad Telegram notifikationer at blive sendt til det specificerede chat id. Uden
 denne tilladelse kan Telegram ikke tillade os at sende notifikationer til dig.',
        'telegram_bot_username_found' => 'Botten blev fundet!<br><a href="%s" target="_blank" rel="noopener"><button
 class="btn btn-primary">Næste skridt</button></a> <br>Dette vil åbne en chat
 med botten. Du skal klikke start eller skrive /start.',
        'telegram_bot_username_error_token' => '401 - Uautoriseret. Du bør sikre dig at dit API token er gyldigt.',
        'telegram_bot_error' => 'Der opstod en fejl under aktivering af Telegram notifikation: %s',
        'jabber' => 'Jabber',
        'jabber_label' => 'Jabber',
        'jabber_description' => 'Din Jabber konto',
        'delete_title' => 'Slet bruger',
        'delete_message' => 'Er du sikker på du vil slette bruger \'%1\'?',
        'deleted' => 'Bruger slettet.',
        'updated' => 'Bruger opdateret.',
        'inserted' => 'Bruger tilføjet.',
        'profile' => 'Profil',
        'profile_updated' => 'Din profil er opdateret.',
        'error_user_name_bad_length' => 'Brugernavn skal være mellem 2 til 64 tegn.',
        'error_user_name_invalid' => 'Brugernavn må kun indholde alfabetiske tegn (a-z, A-Z), tal (0-9), prikker (.)
 og (_).',
        'error_user_name_exists' => 'Det valgte brugernavn findes allerede.',
        'error_user_email_bad_length' => 'E-mail addresser skal være mellem 5 til 255 tegn.',
        'error_user_email_invalid' => 'Den valgte e-mail er ugyldig.',
        'error_user_level_invalid' => 'Det angivet bruger niveau er ugyldig.',
        'error_user_no_match' => 'Brugeren findes ikke.',
        'error_user_password_invalid' => 'Den indtastede adgangskode er ugyldig.',
        'error_user_password_no_match' => 'De to adgangskode er ikke ens.',
    ),
    'log' => array(
        'title' => 'Logposter',
        'type' => 'Type',
        'status' => 'Status',
        'email' => 'E-mail',
        'sms' => 'SMS',
        'pushover' => 'Pushover',
        'telegram' => 'Telegram',
        'jabber' => 'Jabber',
        'no_logs' => 'Intet i loggen',
        'clear' => 'Ryd log',
        'delete_title' => 'Slet log',
        'delete_message' => 'Er du sikker på, at du vil slette <b>alle</b> logfiler?',
    ),
    'servers' => array(
        'server' => 'Server',
        'status' => 'Status',
        'label' => 'Label',
        'domain' => 'Domæne/IP',
        'timeout' => 'Timeout',
        'timeout_description' => 'Antal sekunder som serveren har til at svare.',
        'authentication_settings' => 'Autentificeringsindstillinger',
        'optional' => 'Valgfri',
        'website_username' => 'Brugernavn',
        'website_username_description' => 'Brugernavn til adgang til siden. (Kun Apache autentificering understøttes.)',
        'website_password' => 'Adgangskode',
        'website_password_description' => 'Adgangskode til adgang til siden. Adgangskoden er krypteret i databasen.',
        'fieldset_monitoring' => 'Monitorering',
        'fieldset_permissions' => 'Tilladelser',
        'permissions' => 'Server vil være synlig for følgende brugere',
        'port' => 'Port',
        'custom_port' => 'Tilpasset port',
        'popular_ports' => 'Populære porte',
        'request_method' => 'Forespørgselsmetode',
        'custom_request_method' => 'Tilpasset forespørgselsmetode',
        'popular_request_methods' => 'Populær forespørgselsmetode',
        'post_field' => 'Post felt',
        'post_field_description' => 'Data som sendes via forespørgselsmetoden herover.',
        'please_select' => 'Vælg venligst',
        'type' => 'Type',
        'type_website' => 'Hjemmeside',
        'type_service' => 'Tjeneste',
        'type_ping' => 'Ping',
        'pattern' => 'Søgestreng/mønster',
        'pattern_description' => 'Hvis dette mønster ikke findes på hjemmesiden, vil serveren blive markeret som
 værende offline. Regulære udtryk er tilladt.',
        'pattern_online' => 'Mønster tyder på at',
        'pattern_online_description' => 'Online: Hvis mønster blev fundet på hjemmesiden, vil server blive markeret som
 online. Offline: Hvis møsnter ikke findes på hjemmesiden, vil server blive
 markeret som offline.',
        'redirect_check' => 'Videresend til et amdet domæne er',
        'redirect_check_description' => 'Videresend til et amdet domæne er normalt et dårligt tegn.',
        'allow_http_status' => 'Tillad HTTP status kode',
        'allow_http_status_description' => 'Markér website som online. HTTP Status koder under 400 er markeret som
 online som standard. Opdel med |.',
        'header_name' => 'Header navn',
        'header_value' => 'Header værdi',
        'header_name_description' => 'Case-sensitive.',
        'header_value_description' => 'Regulære udtryk er tilladt.',
        'last_check' => 'Sidst kontrolleret',
        'last_online' => 'Sidst online',
        'last_offline' => 'Sidst offline',
        'monitoring' => 'Overvågning',
        'no_monitoring' => 'Ingen overvågning',
        'email' => 'E-mail',
        'send_email' => 'Send E-mail',
        'sms' => 'SMS',
        'send_sms' => 'Send SMS',
        'pushover' => 'Pushover',
        'send_pushover' => 'Send Pushover notifikation',
        'telegram' => 'Telegram',
        'send_telegram' => 'Send Telegram notifikation',
        'jabber' => 'Jabber',
        'send_jabber' => 'Send Jabber notifikation',
        'users' => 'Brugere',
        'delete_title' => 'Slet server',
        'delete_message' => 'Er du sikker på du vil slette server \'%1\'?',
        'deleted' => 'Server slettet.',
        'updated' => 'Server opdateret.',
        'inserted' => 'Server tilføjet.',
        'latency' => 'Forsinkelse',
        'latency_max' => 'Forsinkelse (maksimum)',
        'latency_min' => 'Forsinkelse (minimum)',
        'latency_avg' => 'Forsinkelse (gennemsnitlig)',
        'online' => 'online',
        'offline' => 'offline',
        'uptime' => 'Oppetid',
        'year' => 'År',
        'month' => 'Måned',
        'week' => 'Uge',
        'day' => 'Dag',
        'hour' => 'Time',
        'warning_threshold' => 'Advarsel grænse',
        'warning_threshold_description' => 'Antallet af fejl, før status skifter til offline.',
        'ssl_cert_expiry_days' => 'SSL certifikat validering',
        'ssl_cert_expiry_days_description' => 'Minimum af tilbageværende dage hvor SSL certifikatet stadig er gyldigt. Brug 0 for at
 deaktivere tjek.',
        'ssl_cert_expired' => 'SSL certifikat udløbet siden',
        'ssl_cert_expiring' => 'SSL certifikat udløber:',
        'chart_last_week' => 'Sidste uge',
        'chart_history' => 'Historie',
        'chart_day_format' => '%d-%m-%Y',
        'chart_long_date_format' => '%d-%m-%Y %H:%M:%S',
        'chart_short_date_format' => '%d/%m %H:%M',
        'chart_short_time_format' => '%H:%M',
        'warning_notifications_disabled_sms' => 'SMS notifikationer er deaktiveret.',
        'warning_notifications_disabled_email' => 'E-mail notifikationer er deaktiveret.',
        'warning_notifications_disabled_pushover' => 'Pushover notifikationer er deaktiveret.',
        'warning_notifications_disabled_telegram' => 'Telegram notifikation er deaktiveret.',
        'warning_notifications_disabled_jabber' => 'Jabber notifikation er deaktiveret.',
        'error_server_no_match' => 'Server ikke fundet.',
        'error_server_label_bad_length' => 'Label skal være mellem et og 255 karakterer.',
        'error_server_ip_bad_length' => 'Domænet/IP skal være mellem et og 255 karakterer.',
        'error_server_ip_bad_service' => 'IP adressen er ikke gyldig.',
        'error_server_ip_bad_website' => 'Websitets URL er ikke gyldigt.',
        'error_server_type_invalid' => 'Den valgte servertype er ikke gyldig.',
        'error_server_warning_threshold_invalid' => 'Advarsels-tærskel skal være et gyldigt tal større end 0.',
        'error_server_ssl_cert_expiry_days' => 'Det tilbageværende antal dage for SSL certifikets validering skal være et gyldigt
 tal større end eller lig med 0.',
    ),
    'config' => array(
        'general' => 'Generelt',
        'site_title' => 'Sidetitel',
        'language' => 'Sprog',
        'show_update' => 'Opdateringer',
        'password_encrypt_key' => 'Adgangskode krypteringsnøgle',
        'password_encrypt_key_note' => 'Denne nøgle bruges til at kryptere adgangskoden, som er gemt på servere og giver adgang til
 websider. Hvis nøglen ændres vil den gemte adgangskode være ugyldig!',
        'proxy' => 'Aktivér proxy',
        'proxy_url' => 'Proxy URL',
        'proxy_user' => 'Proxy brugernavn',
        'proxy_password' => 'Proxy adgangskode',
        'email_status' => 'Tillad at sende e-mail',
        'email_from_email' => 'E-mail fra adresse',
        'email_from_name' => 'E-mail fra navn',
        'email_smtp' => 'Aktiver SMTP',
        'email_smtp_host' => 'SMTP vært',
        'email_smtp_port' => 'SMTP port',
        'email_smtp_security' => 'SMTP sikkerhed',
        'email_smtp_security_none' => 'Ingen',
        'email_smtp_username' => 'SMTP brugernavn',
        'email_smtp_password' => 'SMTP adgangskode',
        'email_smtp_noauth' => 'Efterlad blank hvis det ikke er krævet',
        'sms_status' => 'Tillad at sende SMS beskeder',
        'sms_gateway' => 'SMS Gateway',
        'sms_gateway_username' => 'Gateway brugernavn/apikey',
        'sms_gateway_password' => 'Gateway adgangskode',
        'sms_from' => 'Afsenderens navn.',
        'pushover_status' => 'Tillad at sende Pushover beskeder',
        'pushover_description' => 'Pushover er en service det gør det nemt at modtage real-time notifikationer. Se <a
 href="https://pushover.net/" target="_blank">deres website</a> for yderligere
 information.',
        'pushover_clone_app' => 'Klik her for at oprette din Pushover app',
        'pushover_api_token' => 'Pushover App API Token',
        'pushover_api_token_description' => 'Før du kan benytte Pushover, skal du <a href="%1$s" target="_blank"
 rel="noopener">registrere en app</a> på deres website og indtaste en App
 API Token her.',
        'telegram_status' => 'Tillad afsending af Telegram beskeder',
        'telegram_description' => '<a href="https://telegram.org/" target="_blank">Telegram</a> er en chat app som
 gør det nemt at modtage notifikationer i realtid. Besøg <a
 href="http://docs.phpservermonitor.org/" target="_blank">dokumentation</a> for mere 
 info hjælp til installation.',
        'telegram_api_token' => 'Telegram API Token',
        'telegram_api_token_description' => 'Før du kan bruge Telegram, har du brug for et API token. Besøg <a
 href="http://docs.phpservermonitor.org/"
 target="_blank">dokumentation</a> for hjælp.',
        'jabber_status' => 'Tillad at sende Jabber (XMPP) beskeder',
        'jabber_description' => 'Besøg <a
 href="http://docs.phpservermonitor.org/">dokumentation</a> for yderligere info og installations
  vejledning.',
        'jabber_host' => 'Host',
        'jabber_host_description' => 'Host af din Jabber kontoudbyder. For Google konto brug talk.google.com.',
        'jabber_port' => 'Port',
        'jabber_port_description' => 'Port for din Jabber udbyder. Standard 5222. For Google konto brug 5223.',
        'jabber_username' => 'Brugernavn',
        'jabber_username_description' => 'For Google konto brug inkl. domæne for eksempel eksempel@google.com.',
        'jabber_domain' => 'Domæne',
        'jabber_domain_description' => 'Domæne for din Jabber udbyder. Efterlades tom for Google konto.',
        'jabber_password' => 'Adgangskode',
        'jabber_password_description' => 'Udfyldes kun for at angive eller ændre.',
        'jabber_check' => 'Tjek din Jabber konto hvis besked blev modtaget.',
        'alert_type' => 'Vælg hvornår du vil modtage beskeden',
        'alert_type_description' => '<b>Status ændring:</b> Du vil modtage en notifkation når en server har en
 ændring i status. Fra online -> offline eller offline -> online.<br><br
 /><b>Offline:</b> Du vil modtage en meddelelse, når en server går offline for
 første gang. Eksempelvis hvis dit cronjob kører hvert kvarter, og din server
 går ned kl 01 og kommer først op kl 06,  vil du kun modtage en mail kl
 01.<br><br><b>Altid:</b> Du vil modtage en besked, hver gang scriptet kører og
 et websted er nede, selvom site har været offline i flere timer.',
        'alert_type_status' => 'Status ændret',
        'alert_type_offline' => 'Offline',
        'alert_type_always' => 'Altid',
        'combine_notifications' => 'Kombinér notifikationer',
        'combine_notifications_description' => 'Reducerer antaller af notifikationer ved at kombinere  notifikationer til
 en enkel. (Dette påvirker ikke SMS notifikationer.)',
        'alert_proxy' => 'Selv hvis aktiveret, vil proxy aldrig blive brugt som service',
        'alert_proxy_url' => 'Format: host:port',
        'log_status' => 'Log status',
        'log_status_description' => 'Hvis log status er sat til TRUE, vil monitoren logge hændelsen hver gang status
 ændre sig.',
        'log_email' => 'Log e-mails sendt af systemet',
        'log_sms' => 'Log SMS sendt af systemet',
        'log_pushover' => 'Log pushover besked sendt af scriptet',
        'log_telegram' => 'Log Telegram beskeder sendt af scriptet',
        'log_jabber' => 'Log Jabber beskeder sendt af scriptet',
        'updated' => 'Indstillingerne er blevet opdateret.',
        'tab_email' => 'E-mail',
        'tab_sms' => 'SMS',
        'tab_pushover' => 'Pushover',
        'tab_telegram' => 'Telegram',
        'tab_jabber' => 'Jabber',
        'settings_email' => 'E-mail indstillinger',
        'settings_sms' => 'SMS indstillinger',
        'settings_pushover' => 'Pushover indstillinger',
        'settings_telegram' => 'Telegram indstillinger',
        'settings_jabber' => 'Jabber indstillinger',
        'settings_notification' => 'Meddelelse indstillinger',
        'settings_log' => 'Log indstillinger',
        'settings_proxy' => 'Proxy indstillinger',
        'auto_refresh' => 'Genopfrisk automatisk',
        'auto_refresh_description' => 'Genopfrisk automatisk serversider.<br><span class="small">Tid i sekunder. Hvis
 0 vil siden ikke genopfriske automatisk</span>',
        'test' => 'Test',
        'test_email' => 'En e-mail vil blive sendt til den adresse, der er angivet i din brugerprofil.',
        'test_sms' => 'En SMS vil blive sendt til det nummer, der er angivet i din brugerprofil.',
        'test_pushover' => 'En Pushover notifikation vil blive sendt til brugerens enhed, specificeret i
 brugerprofilen.',
        'test_telegram' => 'A Telegram notifikation vil blive sendt til den chat id som er angivet i din brugerprofil.',
        'test_jabber' => 'A Jabber notifikation vil blive sendt til den jabber konto som er angivet i din brugerprofil.', 
        'send' => 'Send',
        'test_subject' => 'Test',
        'test_message' => 'Test besked',
        'email_sent' => 'E-mail sendt',
        'email_error' => 'Fejl ved afsendelse af e-mail',
        'sms_sent' => 'Sms sendt',
        'sms_error' => 'Fejl ved afsendelse af SMS. %s',
        'sms_error_nomobile' => 'Ikke muligt at sende SMS: Intet gyldigt telefonnummer blev fundet i din profil.',
        'pushover_sent' => 'Pushover notifikation blev sendt',
        'pushover_error' => 'En fejl opstod under afsendelse af Pushover notifikation: %s',
        'pushover_error_noapp' => 'Ikke muligt at sende test notifikation: Intet Pushover App API token fundet i den
 globale konfiguration.',
        'pushover_error_nokey' => 'Ikke muligt at sende test notifikation: Ingen Pushover key fundet i din profil.',
        'telegram_sent' => 'Telegram notifikation sendt',
        'telegram_error' => 'En fejl opstod under afsendelse af Telegram notifikation: %s',
        'telegram_error_notoken' => 'Ikke muligt at sende test notifikation: Intet Telegram API token fundet i den globale
 konfiguration.',
        'telegram_error_noid' => 'Ikke muligt at sende test notifikation: Ingen chat id fundet i din profil.',
        'jabber_sent' => 'Jabber notifikation sendt',
        'jabber_error' => 'En fejl opstod under afsendelse af Jabber notifikation: %s',
        'jabber_error_noconfig' => 'Ikke muligt at sende test notifikation: Ingen Jabber konto angivet i den globale
 konfiguration.',
        'jabber_error_noaccount' => 'Ikke muligt at sende test notifikation: Ingen Jabber konto fundet i din profil.',        
        'log_retention_period' => 'Logs gemmes',
        'log_retention_period_description' => 'Antal dage over hvor længe logs med notifikationer og arkiverede
 serveres oppetid skal gemmes. Indtast 0 for at deaktivere logoprydning.',
        'log_retention_days' => 'dage',
        'user_agent' => 'User Agent',
        'user_agent_key_note' => 'Tilpasset user agent bruges af monitor indenfor kommunikation med eksterne services.',
    ),
    'notifications' => array(
        'off_sms' => 'Serveren \'%LABEL%\' er NEDE: ip=%IP%, port=%PORT%. Fejl=%ERROR%',
        'off_email_subject' => 'VIGTIGT: Server \'%LABEL%\' er NEDE',
        'off_email_body' => 'Det lykkedes ikke at oprette forbindelse til følgende server:<br><br>Server:
 %LABEL%<br>IP: %IP%<br>Port: %PORT%<br>Fejl: %ERROR%<br>Dato: %DATE%',
        'off_pushover_title' => 'Serveren \'%LABEL%\' er NEDE',
        'off_pushover_message' => 'Det lykkedes ikke at oprette forbindelse til følgende server:<br><br>Server:
 %LABEL%<br>IP: %IP%<br>Port: %PORT%<br>Fejl: %ERROR%<br>Dato: %DATE%',
        'off_telegram_message' => 'Kunne ikke forbinde til følgende server:<br><br>Server: %LABEL%<br>IP:
 %IP%<br>Port: %PORT%<br>Fejl: %ERROR%<br>Dato: %DATE%',
        'off_jabber_message' => 'Kunne ikke forbinde til følgende server:<br><br>Server: %LABEL%<br>IP:
 %IP%<br>Port: %PORT%<br>Fejl: %ERROR%<br>Dato: %DATE%', 
        'on_sms' => 'Serveren \'%LABEL%\' KØRER: ip=%IP%, port=%PORT%, it was down for %LAST_OFFLINE_DURATION%',
        'on_email_subject' => 'VIGTIGT: Serveren \'%LABEL%\' KØRER',
        'on_email_body' => 'Serveren \'%LABEL%\' kører igen, it was down for %LAST_OFFLINE_DURATION%:<br><br>Server:
 %LABEL%<br>IP: %IP%<br>Port: %PORT%<br>Dato: %DATE%',
        'on_pushover_title' => 'Serveren \'%LABEL%\' KØRER',
        'on_pushover_message' => 'Serveren \'%LABEL%\' kører igen, it was down for
 %LAST_OFFLINE_DURATION%:<br><br>Server: %LABEL%<br>IP: %IP%<br>Port: %PORT%<br>Dato:
 %DATE%',
        'combi_off_email_message' => '<ul><li>Server: %LABEL%</li><li>IP: %IP%</li><li>Port: %PORT%</li><li>Fejl::
 %ERROR%</li><li>Dato: %DATE%</li></ul>',
        'combi_off_pushover_message' => '<ul><li>Server: %LABEL%</li><li>IP: %IP%</li><li>Port: %PORT%</li><li>Fejl:
 %ERROR%</li><li>Dato: %DATE%</li></ul>',
        'combi_off_telegram_message' => '- Server: %LABEL%<br>- IP: %IP%<br>- Port: %PORT%<br>- Fejl: %ERROR%<br>-
 Date: %DATE%<br><br>',
        'combi_off_jabber_message' => '- Server: %LABEL%<br>- IP: %IP%<br>- Port: %PORT%<br>- Fejl: %ERROR%<br>-
 Dato: %DATE%<br><br>',
        'combi_on_email_message' => '<ul><li>Server: %LABEL%</li><li>IP: %IP%</li><li>Port: %PORT%</li><li>Nedetid:
 %LAST_OFFLINE_DURATION%</li><li>Dato: %DATE%</li></ul>',
        'combi_on_pushover_message' => '<ul><li>Server: %LABEL%</li><li>IP: %IP%</li><li>Port:
 %PORT%</li><li>Nedetid: %LAST_OFFLINE_DURATION%</li><li>Dato:
 %DATE%</li></ul>',
        'combi_on_telegram_message' => '- Server: %LABEL%<br>- IP: %IP%<br>- Port: %PORT%<br>- Nedetid:
 %LAST_OFFLINE_DURATION%<br>- Dato: %DATE%<br><br>',
        'combi_on_jabber_message' => '- Server: %LABEL%<br>- IP: %IP%<br>- Port: %PORT%<br>- Nedetid:
 %LAST_OFFLINE_DURATION%<br>- Dato: %DATE%<br><br>',
        'combi_email_subject' => 'IMPORTANT: \'%UP%\' servere OP igen, \'%DOWN%\' serverer NEDE',
        'combi_pushover_subject' => '\'%UP%\' servere OP igen, \'%DOWN%\' servere NEDE',
        'combi_email_message' => '<b>Følgende servere gik ned:</b><br>%DOWN_SERVERS%<br><b>Følgende servere er oppe igen:</b><br>%UP_SERVERS%',
        'combi_pushover_message' => '<b>Følgende servere gik ned:</b><br>%DOWN_SERVERS%<br><b>Følgende servere er oppe igen:</b><br>%UP_SERVERS%',
        'combi_telegram_message' => '<b>Følgende servere gik ned:</b><br>%DOWN_SERVERS%<br><b>Følgende servere er oppe igen:</b><br>%UP_SERVERS%',
        'combi_jabber_message' => '<b>Følgende servere gik ned:</b><br>%DOWN_SERVERS%<br><b>Følgende servere er oppe igen:</b><br>%UP_SERVERS%',
    ),
    'login' => array(
        'welcome_usermenu' => 'Velkommen, %user_name%',
        'title_sign_in' => 'Log ind',
        'title_forgot' => 'Glemt adgangskode?',
        'title_reset' => 'Nulstil din adgangskode',
        'submit' => 'Indsend',
        'remember_me' => 'Husk kode',
        'login' => 'Log ind',
        'logout' => 'Log ud',
        'username' => 'Brugernavn',
        'password' => 'Adgangskode',
        'password_repeat' => 'Skriv adgangskode igen',
        'password_forgot' => 'Glemt adgangskode?',
        'password_reset' => 'Nulstil adgangskode',
        'password_reset_email_subject' => 'Nulstil din adgangskode for PHP Server Monitor',
        'password_reset_email_body' => 'Brug venligst følgende link for at nulstille din adgangskode. Bemærk at
 linkets gyldighed udløber efter en time.<br><br>%link%',
        'error_user_incorrect' => 'Det angivet brugernavn kunne ikke findes.',
        'error_login_incorrect' => 'Oplysningerne stemmer ikke overens.',
        'error_login_passwords_nomatch' => 'De angivne adgangskoder er ikke ens.',
        'error_reset_invalid_link' => 'Følgende link er ugyldigt.',
        'success_password_forgot' => 'En e-mail er blevet sendt til dig med oplysninger om, hvordan du nulstiller din
 adgangskode.',
        'success_password_reset' => 'Din adgangskode er blevet nulstillet. Log venligst ind igen.',
    ),
    'error' => array(
        '401_unauthorized' => 'Uautoriseret',
        '401_unauthorized_description' => 'Du har ikke rettigheder til at se denne side.',
    ),
);
