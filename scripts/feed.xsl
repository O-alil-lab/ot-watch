<?xml version="1.0" encoding="UTF-8"?>
<!-- Affichage lisible du flux RSS OT Watch dans un navigateur (aucune ressource externe). -->
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:output method="html" encoding="UTF-8" indent="yes"/>
  <xsl:template match="/rss/channel">
    <html lang="fr">
      <head>
        <meta charset="utf-8"/>
        <meta name="viewport" content="width=device-width, initial-scale=1"/>
        <title><xsl:value-of select="title"/> — flux RSS</title>
        <style>
          body{font-family:system-ui,'Segoe UI',Arial,sans-serif;background:#0b1220;color:#e2e8f0;margin:0;padding:24px;line-height:1.55}
          .wrap{max-width:860px;margin:auto}
          h1{font-size:22px;margin:0 0 6px}
          .how{background:#1e293b;border-radius:10px;padding:14px 16px;margin:14px 0 22px;font-size:14px}
          .how code{background:#0f172a;color:#f59e0b;padding:2px 6px;border-radius:4px;word-break:break-all}
          .item{border-bottom:1px solid #1e293b;padding:12px 0}
          .item a{color:#60a5fa;font-weight:600;text-decoration:none}
          .item p{color:#94a3b8;margin:4px 0 0;font-size:14px}
          .back{color:#f59e0b}
        </style>
      </head>
      <body>
        <div class="wrap">
          <h1>📡 <xsl:value-of select="title"/></h1>
          <div><xsl:value-of select="description"/> · mis à jour le <xsl:value-of select="lastBuildDate"/></div>
          <div class="how">
            <b>Comment s'abonner ?</b> Copiez cette adresse dans votre lecteur RSS
            (Feedly, Inoreader, Thunderbird, Outlook…) :<br/>
            <code>https://o-alil-lab.github.io/ot-watch/feed.xml</code><br/>
            Vous recevrez automatiquement les nouvelles CVE OT/ICS prioritaires et les avis CISA, sans inscription ni e-mail.
          </div>
          <xsl:for-each select="item">
            <div class="item">
              <a href="{link}"><xsl:value-of select="title"/></a>
              <p><xsl:value-of select="description"/></p>
            </div>
          </xsl:for-each>
          <p><a class="back" href="./">← Retour au tableau de bord OT Watch</a></p>
        </div>
      </body>
    </html>
  </xsl:template>
</xsl:stylesheet>
