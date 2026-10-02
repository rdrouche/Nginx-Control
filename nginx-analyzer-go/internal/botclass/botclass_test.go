package botclass

import "testing"

func TestClassifyAgent(t *testing.T) {
	t.Run("un navigateur reel est humain", func(t *testing.T) {
		r := ClassifyAgent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36")
		if r.IsBot == nil || *r.IsBot != false || r.Category != "human" {
			t.Fatalf("got %+v", r)
		}
	})
	t.Run("googlebot -> bon robot", func(t *testing.T) {
		r := ClassifyAgent("Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)")
		if r.IsBot == nil || *r.IsBot != true || r.Category != "good" {
			t.Fatalf("got %+v", r)
		}
	})
	t.Run("bingbot -> bon robot", func(t *testing.T) {
		if ClassifyAgent("bingbot/2.0").Category != "good" {
			t.Fatal("expected good")
		}
	})
	t.Run("GPTBot -> robot IA", func(t *testing.T) {
		if ClassifyAgent("Mozilla/5.0 (compatible; GPTBot/1.0)").Category != "ai" {
			t.Fatal("expected ai")
		}
	})
	t.Run("ClaudeBot -> robot IA", func(t *testing.T) {
		if ClassifyAgent("ClaudeBot/1.0").Category != "ai" {
			t.Fatal("expected ai")
		}
	})
	t.Run("AhrefsBot -> robot indesirable", func(t *testing.T) {
		if ClassifyAgent("Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)").Category != "bad" {
			t.Fatal("expected bad")
		}
	})
	t.Run("scanner de securite -> robot indesirable", func(t *testing.T) {
		if ClassifyAgent("Shodan").Category != "bad" {
			t.Fatal("expected bad")
		}
	})
	t.Run("client HTTP generique -> robot non catalogue", func(t *testing.T) {
		if ClassifyAgent("python-requests/2.31.0").Category != "unknown" {
			t.Fatal("expected unknown")
		}
		if ClassifyAgent("curl/8.4.0").Category != "unknown" {
			t.Fatal("expected unknown")
		}
	})
	t.Run("en-tete absent -> ni humain ni robot, distinct des deux", func(t *testing.T) {
		for _, ua := range []string{"", ""} {
			r := ClassifyAgent(ua)
			if r.IsBot != nil || r.Category != "" {
				t.Fatalf("got %+v", r)
			}
		}
	})
	t.Run("un robot connu ne doit jamais retomber dans la categorie generique", func(t *testing.T) {
		r := ClassifyAgent("Googlebot-Image/1.0")
		if r.Category != "good" {
			t.Fatalf("ne doit pas devenir unknown, got %q", r.Category)
		}
	})
}
