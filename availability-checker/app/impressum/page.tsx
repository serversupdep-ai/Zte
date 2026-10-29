import type { Metadata } from "next";

export const metadata: Metadata = { title: "Impressum · Namevet" };

// Set NEXT_PUBLIC_CONTACT_EMAIL in the environment: § 5 DDG requires an electronic contact.
const email = process.env.NEXT_PUBLIC_CONTACT_EMAIL;

export default function Impressum() {
  return (
    <main className="page legal">
      <h1>Impressum</h1>
      <h2>Angaben gemäß § 5 DDG</h2>
      <p>
        Mika Stiebitz
        <br />
        Harmoniestraße 10
        <br />
        90489 Nürnberg
      </p>
      {email && (
        <>
          <h2>Kontakt</h2>
          <p>
            E-Mail: <a href={`mailto:${email}`}>{email}</a>
          </p>
        </>
      )}
      <h2>Haftung für Inhalte</h2>
      <p>
        Die Ergebnisse dieses Tools (Domain-, App-Store-, Web- und Registerprüfung) sind eine erste, automatisierte
        Orientierung und stellen keine Rechts- oder Markenrechtsberatung dar. Für Richtigkeit, Vollständigkeit und
        Aktualität der Ergebnisse wird keine Gewähr übernommen. Eine Markenrecherche sollte vor einer Nutzung oder
        Anmeldung eines Namens immer zusätzlich in den amtlichen Registern und gegebenenfalls durch eine
        fachkundige Person erfolgen.
      </p>
      <h2>Haftung für Links</h2>
      <p>
        Dieses Angebot enthält Links zu externen Websites Dritter, auf deren Inhalte kein Einfluss besteht. Für diese
        fremden Inhalte wird keine Gewähr übernommen. Verantwortlich ist stets der jeweilige Anbieter.
      </p>
    </main>
  );
}
