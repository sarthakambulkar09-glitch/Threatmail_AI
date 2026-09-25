import { jsPDF } from 'jspdf';
import { EmailThreatReport } from '../types';

export function generateForensicPdf(report: EmailThreatReport): void {
  const doc = new jsPDF({
    orientation: 'portrait',
    unit: 'mm',
    format: 'a4',
  });

  const pageWidth = doc.internal.pageSize.getWidth();
  const pageHeight = doc.internal.pageSize.getHeight();
  let y = 15;

  // Background Header Bar
  doc.setFillColor(15, 20, 31); // Dark SOC Gray #0f141f
  doc.rect(0, 0, pageWidth, 28, 'F');

  // Accent Line
  const accentColor =
    report.riskScore >= 75 ? [239, 68, 68] : report.riskScore >= 40 ? [245, 158, 11] : [34, 197, 94];
  doc.setFillColor(accentColor[0], accentColor[1], accentColor[2]);
  doc.rect(0, 27, pageWidth, 1.5, 'F');

  // SOC Brand Title
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(14);
  doc.setTextColor(255, 255, 255);
  doc.text('THREATMAIL AI // SOC FORENSIC INCIDENT REPORT', 14, 12);

  doc.setFontSize(8);
  doc.setFont('helvetica', 'normal');
  doc.setTextColor(156, 163, 175);
  doc.text(
    `INCIDENT ID: INC-${report.id.slice(0, 10).toUpperCase()}  |  TIMESTAMP: ${new Date().toISOString()}`,
    14,
    19
  );
  doc.text(`INSFORGE ENGINE v2.4  |  SECURITY CLEARANCE: TLP:AMBER`, 14, 24);

  y = 36;

  // Executive Threat Classification Card
  doc.setFillColor(243, 244, 246);
  doc.rect(14, y, pageWidth - 28, 22, 'F');
  doc.setDrawColor(209, 213, 219);
  doc.rect(14, y, pageWidth - 28, 22, 'S');

  doc.setFont('helvetica', 'bold');
  doc.setFontSize(10);
  doc.setTextColor(31, 41, 55);
  doc.text('CLASSIFICATION:', 18, y + 8);

  // Classification Badge
  doc.setFontSize(12);
  doc.setTextColor(accentColor[0], accentColor[1], accentColor[2]);
  doc.text(`${report.classification.toUpperCase()}`, 56, y + 8);

  doc.setFontSize(10);
  doc.setTextColor(31, 41, 55);
  doc.text('RISK SCORE:', 18, y + 16);

  doc.setFontSize(12);
  doc.setTextColor(accentColor[0], accentColor[1], accentColor[2]);
  doc.text(`${report.riskScore} / 100`, 56, y + 16);

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(9);
  doc.setTextColor(75, 85, 99);
  doc.text(`ATTACK VECTOR: ${report.attackVector}`, 110, y + 8);
  doc.text(`CONTAINMENT STATUS: ${report.status.toUpperCase()}`, 110, y + 16);

  y += 28;

  // Section 1: Email Metadata
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(10);
  doc.setTextColor(17, 24, 39);
  doc.text('1. TARGET EMAIL METADATA', 14, y);
  doc.setDrawColor(229, 231, 235);
  doc.line(14, y + 2, pageWidth - 14, y + 2);
  y += 7;

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(8.5);
  doc.setTextColor(55, 65, 81);

  doc.text(`Subject: ${report.subject.slice(0, 80)}`, 14, y);
  y += 5;
  doc.text(`From: "${report.sender.name}" <${report.sender.email}> (Domain: ${report.sender.domain})`, 14, y);
  y += 5;
  doc.text(`To: ${report.recipient}`, 14, y);
  y += 5;
  doc.text(`Date Sent: ${report.date}`, 14, y);
  y += 5;
  doc.text(`Message-ID: ${report.headers.messageId.slice(0, 80)}`, 14, y);
  y += 7;

  // Section 2: Security Headers & Origin IP
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(10);
  doc.setTextColor(17, 24, 39);
  doc.text('2. AUTHENTICATION HEADERS & GEOLOCATION', 14, y);
  doc.line(14, y + 2, pageWidth - 14, y + 2);
  y += 7;

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(8.5);
  doc.text(
    `SPF: ${(report.headers.spfStatus || 'neutral').toUpperCase()}   |   DKIM: ${(report.headers.dkimStatus || 'neutral').toUpperCase()}   |   DMARC: ${(report.headers.dmarcStatus || 'neutral').toUpperCase()}`,
    14,
    y
  );
  y += 5;
  doc.text(
    `Origin Server IP: ${report.senderIp || 'Unknown'}  |  Location: ${report.senderLocation?.city || 'Unknown'}, ${report.senderLocation?.country || 'Unknown'} (${report.senderLocation?.isp || 'Unknown ISP'})`,
    14,
    y
  );
  y += 5;
  if (report.travelRoute && report.travelRoute.length > 0) {
    const routeSummary = report.travelRoute.map((h) => `${h.ip} (${h.location?.country || 'Relay'})`).join(' -> ');
    doc.text(`Travel Route Hops: ${routeSummary.slice(0, 100)}`, 14, y);
    y += 5;
  }
  y += 3;

  // Section 3: Extracted Links & Attachments
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(10);
  doc.setTextColor(17, 24, 39);
  doc.text('3. EXTRACTED HYPERLINKS & ATTACHMENTS', 14, y);
  doc.line(14, y + 2, pageWidth - 14, y + 2);
  y += 7;

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(8);
  if (report.extractedLinks.length === 0) {
    doc.text('No embedded hyperlinks detected in payload body.', 14, y);
    y += 5;
  } else {
    report.extractedLinks.slice(0, 5).forEach((link) => {
      const tag = link.isSuspicious ? '[SUSPICIOUS DOMAIN]' : '[STANDARD]';
      doc.setTextColor(link.isSuspicious ? 220 : 75, link.isSuspicious ? 38 : 85, link.isSuspicious ? 38 : 99);
      doc.text(`• ${tag} ${link.url.slice(0, 95)}`, 14, y);
      y += 4.5;
    });
  }

  if (report.attachments.length > 0) {
    y += 2;
    doc.setTextColor(55, 65, 81);
    doc.setFont('helvetica', 'bold');
    doc.text('Attachments:', 14, y);
    y += 4.5;
    doc.setFont('helvetica', 'normal');
    report.attachments.forEach((att) => {
      const risk = att.isSuspicious ? 'CRITICAL RISK EXTENSION' : 'LOW RISK';
      doc.text(`• ${att.filename} (${Math.round(att.size / 1024)} KB, ${att.mimeType}) - ${risk}`, 18, y);
      y += 4.5;
    });
  }
  y += 3;

  // Section 4: Gemini AI Threat Hunter Forensic Explanation
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(10);
  doc.setTextColor(17, 24, 39);
  doc.text('4. GEMINI AI SOC THREAT HUNTER ANALYSIS', 14, y);
  doc.line(14, y + 2, pageWidth - 14, y + 2);
  y += 7;

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(8.5);
  doc.setTextColor(55, 65, 81);

  // Split explanation across lines nicely
  const explanationLines = doc.splitTextToSize(report.threatExplanation, pageWidth - 28);
  doc.text(explanationLines, 14, y);
  y += explanationLines.length * 4.5 + 3;

  // IoCs
  if (report.indicatorsOfCompromise && report.indicatorsOfCompromise.length > 0) {
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(9);
    doc.setTextColor(185, 28, 28);
    doc.text('Indicators of Compromise (IoCs):', 14, y);
    y += 5;
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(8);
    doc.setTextColor(55, 65, 81);
    report.indicatorsOfCompromise.forEach((ioc) => {
      doc.text(`[!] ${ioc}`, 18, y);
      y += 4.5;
    });
    y += 2;
  }

  // Section 5: Mitigation Recommendations
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(10);
  doc.setTextColor(17, 24, 39);
  doc.text('5. SOC CONTAINMENT & REMEDIATION PLAYBOOK', 14, y);
  doc.line(14, y + 2, pageWidth - 14, y + 2);
  y += 7;

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(8.5);
  doc.setTextColor(55, 65, 81);
  const mitigationLines = doc.splitTextToSize(report.mitigationRecommendation, pageWidth - 28);
  doc.text(mitigationLines, 14, y);
  y += mitigationLines.length * 4.5 + 4;

  // Footer
  doc.setFillColor(15, 20, 31);
  doc.rect(0, pageHeight - 12, pageWidth, 12, 'F');
  doc.setFont('helvetica', 'normal');
  doc.setFontSize(7);
  doc.setTextColor(156, 163, 175);
  doc.text(
    'CONFIDENTIAL // FOR AUTHORIZED SOC ANALYSTS ONLY // GENERATED BY THREATMAIL AI // INSFORGE BACKEND ENGINE',
    14,
    pageHeight - 5
  );

  // Trigger download in browser
  const filename = `ThreatMail-Forensic-Report-${report.id.slice(0, 8)}.pdf`;
  doc.save(filename);
}
