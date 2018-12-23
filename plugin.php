<?php

class KokenPasswordProtection extends KokenPlugin {

	private $url;
	private $protected_albums = false;
	private $album_id = false;

	function __construct()
	{
		$this->database_fields = array(
			'albums' => array(
				'koken_password_protect' => array(
					'type' => 'TINYINT',
					'constraint' => 1,
					'default' => 0,
				),
				'koken_password_protect_password' => array(
					'type' => 'VARCHAR',
					'constraint' => 255,
					'null' => true,
				)
			)
		);

		$this->register_hook('site.url', 'open_site');
		$this->register_hook('albums.listing', 'listing');

		$this->register_filter('site.api_data', 'filter_api_data');
		$this->register_filter('api.album', 'filter_album');
		$this->register_filter('api.albums.listing.options', 'listing_options');
		$this->register_filter('site.api_url', 'filter_api_url');
		$this->register_filter('site.cache.write.path', 'filter_write_cache_path');
		$this->register_filter('site.cache.read.path', 'filter_read_cache_path');

		$this->register_template_folder($this->get_file_path() . '/templates');
	}

	private function protect_site()
	{
		return $this->data->scope === 'site';
	}

	function filter_read_cache_path($path)
	{
		if ($this->protect_site())
		{
			$path .= '-protected';
		}
		else
		{
			foreach ($this->get_protected_albums() as $album)
			{
				if (strpos($path, $album['__koken_url']) !== false)
				{
					$path .= '-protected-album-' . $album['id'];

					$this->check_album_authentication($album);

					break;
				}
			}
		}

		return $path;
	}

	function filter_write_cache_path($path)
	{
		if (strpos($path, '/login/') !== false)
		{
			return false;
		}

		return $path;
	}

	function listing_options($options)
	{
		if (isset($options['koken_password_protect']))
		{
			$options['visibility'] = 'private';
			$options['flat'] = true;
		}

		return $options;
	}

	function listing($content, $options)
	{
		if (isset($options['koken_password_protect']))
		{
			$content->where('koken_password_protect', (int) $options['koken_password_protect']);
		}
	}

	function filter_album($album, $albumObject, $options)
	{
		if (isset($options['__disable_filter'])) return $album;

		if ($album['visibility']['raw'] === 'private')
		{
			$album['koken_password_protect'] = (int) $album['koken_password_protect'] === 1;

			if ($album['koken_password_protect'])
			{
				$album['allow_max_download'] = true;
			}

			if ($album['level'] > 1)
			{
				$valid_passwords = $this->get_valid_passwords($album);

				if (empty($valid_passwords))
				{
					$album['koken_password_parent_password'] = false;
				}
				else
				{
					usort($valid_passwords, function($a, $b)
					{
						return $a['level'] < $b['level'] ? -1 : 1;
					});

					$top = array_pop($valid_passwords);

					$album['koken_password_parent_password'] = $top['password'];
				}
			}
		}
		else
		{
			unset($album['koken_password_protect']);
			unset($album['koken_password_protect_password']);
		}

		return $album;
	}

	function filter_api_url($url)
	{
		if ($this->protect_site()) return $url;

		if (strpos($url, 'koken_password_protect:1') !== false || preg_match('~/albums/(slug:)?[^:/]+/.*~', $url) || preg_match('~/content/.*/context:(slug-[^/]+|\d+)/~', $url, $match))
		{

			if (isset($match)) {
				$album = $this->get_api('/albums/' . preg_replace('/-/', ':', $match[1], 1), true);

				if (isset($album['visibility']['raw']) && $album['visibility']['raw'] !== 'private') {
					return $url;
				}
			}

			$url .= '/visibility:album/token:' . $this->request_read_token();
		}

		return $url;
	}

	function filter_api_data($data)
	{
		if ($this->protect_site()) return $data;

		if (isset($data['album']) && $data['album']['visibility']['raw'] === 'private')
		{
			$this->album_id = $data['album']['id'];
			$this->check_album_authentication($data['album']);
		}

		return $data;
	}

	private function check_cookie($cookieName, $password)
	{
		return isset($_COOKIE[$cookieName]) && $_COOKIE[$cookieName] === (string) $password;
	}

	private function check_album_authentication($album)
	{
		$approved = $this->check_cookie('koken_password_protect__album_master', $this->data->master_password);

		if (!$approved)
		{
			$passwords = $this->get_valid_passwords($album);

			foreach ($passwords as $password_album) {
				$cookie = 'koken_password_protect__album_' . $password_album['id'];
				if ($this->check_cookie($cookie, $password_album['password']))
				{
					$approved = true;
					break;
				}
			}
		}

		if ($approved)
		{
			$this->add_body_class('k-password-protected');

			return;
		}

		$this->redirect_to_login($album['id']);
	}

	private function redirect_to_login($resource = null)
	{
		$params = array(
			'return_to' => $this->url,
		);

		if ($resource)
		{
			$params['album'] = $resource;
		}

		$this->redirect('/login/', $params);
	}

	private function get_valid_passwords($album)
	{
		return array_map(function($filtered_album)
		{
			return array(
				'id' => $filtered_album['id'],
				'password' => $filtered_album['koken_password_protect_password'],
				'level' => $filtered_album['level']
			);
		}, array_filter($this->get_protected_albums(), function($password_album) use ($album)
		{
			return in_array($album['left_id'], range($password_album['left_id'], $password_album['right_id'] - 1));
		}));
	}

	private function find_matching_password($password, $album_id)
	{
		$album = $this->get_api('/albums/' . $album_id, true);
		$passwords = $this->get_valid_passwords($album);

		return array_reduce(array_filter($passwords, function($password_album) use ($password)
		{
			return $password === (string) $password_album['password'];
		}), function($carry, $item) {
			return is_null($carry) || $item['level'] < $carry['level'] ? $item : $carry;
		});
	}

	private function get_protected_albums()
	{
		if ($this->protected_albums === false)
		{
			if (class_exists('Album'))
			{
				$a = new Album;
				$data = $a->listing(array(
					'flat' => 1,
					'koken_password_protect' => 1,
					'with_covers' => 0,
					'auth' => true,
					'visibility' => 'private',
					'__disable_filter' => true,
				));
			}
			else
			{
				$data = $this->get_api('/albums/flat:1/koken_password_protect:1/with_covers:0/visibility:private', true);
			}
			$this->protected_albums = $data['albums'];
		}

		return $this->protected_albums;
	}

	function open_site($url)
	{
		$this->url = $url;

		if (isset($_POST['password']) && $url === '/login/')
		{
			$provided_password = (string) $_POST['password'];

			if ($this->protect_site())
			{
				$password = $this->data->password;
				$cookie = 'koken_password_protect__site';
			}
			else if (isset($_GET['album']))
			{
				if (!empty($this->data->master_password) && $provided_password === $this->data->master_password)
				{
					$password = $this->data->master_password;
					$cookie = 'koken_password_protect__album_master';
				}
				else
				{
					$album = $this->find_matching_password($provided_password, $_GET['album']);

					if ($album)
					{
						$password = (string) $album['password'];
						$cookie = 'koken_password_protect__album_' . $album['id'];
					}
					else
					{
						$password = null;
					}
				}
			}
			else
			{
				return;
			}

			if ($provided_password === $password)
			{
				$expires = (int) $this->data->expire;

				if ($expires > 0)
				{
					$expires += time();
				}

				setcookie($cookie, $password, $expires, '/', null, false, true);
				setcookie('koken_password_protect_session_length', $this->data->expire, $expires, '/', null, false, true);

				$redirect = isset($_GET['return_to']) ? urldecode($_GET['return_to']) : '/';

				$this->redirect($redirect);
			}
			else
			{
				$this->set_message('koken_password_error', 'Incorrect password. Please try again.');
			}
		}

		if ($this->protect_site())
		{
			if ($this->check_cookie('koken_password_protect__site', $this->data->password))
			{
				$this->add_body_class('k-password-protected');

				return;
			}

			$whitelist = array('/login/', '/settings.css.lens', '/koken.js');

			if (!in_array($url, $whitelist))
			{
				$this->redirect_to_login();
			}
		}
	}
}
