const APPS_SCRIPT_URL =
  'https://script.google.com/macros/s/AKfycbyUNtzfkfGlXjnJgqzr1Y8BybDZPxIrkYn6oo3daz8uq-7p0bKQcI-dzs44M-d8NEIt/exec';

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // Personal calendar feed
    if (
      request.method === 'GET' &&
      url.pathname.startsWith('/calendar/')
    ) {
      const token = decodeURIComponent(
        url.pathname.substring('/calendar/'.length)
      ).trim();

      if (!token) {
        return new Response('Calendar token missing.', {
          status: 400
        });
      }

      try {
        const upstream = await fetch(
          APPS_SCRIPT_URL +
            '?calendarToken=' +
            encodeURIComponent(token),
          {
            method: 'GET',
            redirect: 'follow'
          }
        );

        const body = await upstream.text();

        return new Response(body, {
          status: upstream.status,
          headers: {
            'Content-Type': 'text/calendar; charset=utf-8',
            'Cache-Control': 'no-cache, no-store, must-revalidate',
            'Access-Control-Allow-Origin': '*'
          }
        });
      } catch (error) {
        console.error('Calendar proxy error:', error);

        return new Response('Calendar feed unavailable.', {
          status: 502
        });
      }
    }

    // Health check
    if (request.method === 'GET') {
      return new Response(
        'IPFL Bot webhook is running.',
        {
          status: 200,
          headers: {
            'Content-Type': 'text/plain; charset=utf-8'
          }
        }
      );
    }

    if (request.method !== 'POST') {
      return new Response('Method Not Allowed', {
        status: 405
      });
    }

    // Telegram webhook proxy
    try {
      const body = await request.text();

      await fetch(APPS_SCRIPT_URL, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: body,
        redirect: 'follow'
      });

      return new Response('OK', {
        status: 200
      });
    } catch (error) {
      console.error('Webhook proxy error:', error);

      // Prevent Telegram retry storm
      return new Response('OK', {
        status: 200
      });
    }
  }
};