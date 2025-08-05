package org.uic.barcode;

import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.time.Instant;
import java.time.ZoneId;
import java.util.Date;
import java.util.TimeZone;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.uic.barcode.ticket.EncodingFormatException;
import org.uic.barcode.ticket.api.impl.SimpleIssuingDetail;
import org.uic.barcode.ticket.api.impl.SimpleOpenTicket;
import org.uic.barcode.ticket.api.impl.SimpleUicRailTicket;
import org.uic.barcode.ticket.api.spec.IIssuingDetail;
import org.uic.barcode.ticket.api.spec.IOpenTicket;
import org.uic.barcode.ticket.api.spec.IUicRailTicket;

public class Main {
    public static void main(String[] args) throws IOException, Exception {
        // ==== Setup ====
        final IIssuingDetail issuingDetail = new SimpleIssuingDetail();
        final IOpenTicket openTicket = new SimpleOpenTicket();
        final IUicRailTicket ticket = new SimpleUicRailTicket();

        issuingDetail.setIssuingDate(Date.from(Instant.parse("2017-07-08T10:15:30Z")));

        openTicket.setValidFrom(Date.from(Instant.parse("2017-12-01T00:05:00Z")));

        openTicket.addActivatedDay(Date.from(Instant.parse("2017-12-01T00:00:00Z")));
        openTicket.addActivatedDay(Date.from(Instant.parse("2018-01-01T00:00:00Z")));

        System.out.println("Activated days before encoding:");
        openTicket.getActivatedDays().stream().map(Date::toInstant).forEach(System.out::println);
        System.out.println("");

        ticket.setIssuerDetails(issuingDetail);
        ticket.addOpenTicket(openTicket);

        // ==== WITH a Europe/Paris timezone (UTC+1 in winter) ====
        TimeZone.setDefault(TimeZone.getTimeZone(ZoneId.of("Europe/Paris")));

        final byte[] encodedParis = getEncoded(ticket);

        final IUicRailTicket decodedParis = getDecoded(encodedParis);

        System.out.println("Decoded activated days using UTC+1 timezone");
        decodedParis.getDocumentData().stream()
                .findFirst()
                .ifPresent(doc -> ((IOpenTicket) doc).getActivatedDays()
                        .stream()
                        .map(Date::toInstant)
                        .forEach(System.out::println));
        System.out.println("");
        // One hour is removed, since it is implicitly do a conversion using the
        // default timezone (UTC to CET)

        // ==== WITH a UTC timezone ====
        TimeZone.setDefault(TimeZone.getTimeZone(ZoneId.of("UTC")));

        final byte[] encodedUtc = getEncoded(ticket);
        final IUicRailTicket decodedUtc = getDecoded(encodedUtc);

        System.out.println("Decoded activated days using UTC timezone");
        decodedUtc.getDocumentData().stream()
                .findFirst()
                .ifPresent(doc -> ((IOpenTicket) doc).getActivatedDays()
                        .stream()
                        .map(Date::toInstant)
                        .forEach(System.out::println));
        System.out.println("");
        // We get the right activated days, the implicit timezone conversion
        // doesn't change anything since it UTC to UTC

        // Output:
        // Activated days before encoding:
        // 2017-12-01T00:00:00Z
        // 2018-01-01T00:00:00Z
        //
        // Decoded activated days using UTC+1 timezone
        // 2017-11-30T23:00:00Z
        // 2017-12-31T23:00:00Z
        //
        // Decoded activated days using UTC timezone
        // 2017-12-01T00:00:00Z
        // 2018-01-01T00:00:00Z
    }

    private static byte[] getEncoded(final IUicRailTicket ticket)
            throws IOException, EncodingFormatException, NoSuchAlgorithmException, Exception {
        Encoder encoder = new Encoder(ticket, null, Encoder.UIC_BARCODE_TYPE_CLASSIC, 1, 2);

        final String shaPlusDsaOid = "1.2.840.10040.4.3";
        Security.addProvider(new BouncyCastleProvider());

        Provider provider = Security.getProvider("BC");

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA", provider);
        keyGen.initialize(1024, new SecureRandom());

        final KeyPair pair = keyGen.generateKeyPair();
        final PrivateKey privateKey = pair.getPrivate();

        Security.addProvider(new BouncyCastleProvider());

        final String ricsCode = "8888";
        encoder.signLevel1(ricsCode, privateKey, shaPlusDsaOid, "1", provider);
        return encoder.encode();
    }

    private static IUicRailTicket getDecoded(byte[] encoded)
            throws IOException, EncodingFormatException, NoSuchAlgorithmException, Exception {
        final Decoder decoder = new Decoder(encoded);

        IUicRailTicket ticket = decoder.getStaticFrame().getuFlex().getTicket();
        return ticket;
    }
}
