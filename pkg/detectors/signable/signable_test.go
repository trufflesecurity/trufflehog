package signable

import (
	"context"
	"testing"
)

func TestSignable_Pattern(t *testing.T) {
	tests := []struct {
		name        string
		data        string
		shouldMatch bool
		match       string
	}{
		// True positives
		{
			name:        "valid",
			data:        `const signableToken = '40a1cd917bff1288f699a94a75b37a1a'`,
			shouldMatch: true,
			match:       "40a1cd917bff1288f699a94a75b37a1a",
		},

		// False positives
		{
			name: `invalid_assignable_yarn`,
			data: `"  babel-helper-explode-assignable-expression@^6.24.1:
    version "6.24.1"
    resolved "https://registry.npmjs.org/babel-helper-explode-assignable-expression/-/babel-helper-explode-assignable-expression-6.24.1.tgz#f25b82cf7dc10433c55f70592d5746400ac22caa"
    dependencies:
      babel-runtime "^6.22.0"
      babel-traverse "^6.24.1"
      babel-types "^6.24.1"`,
			shouldMatch: false,
		},
		{
			name: `invalid_assignable_yarn`,
			data: `"@babel/helper-explode-assignable-expression@^7.16.7":
  version "7.16.7"
  resolved "https://registry.yarnpkg.com/@babel/helper-explode-assignable-expression/-/helper-explode-assignable-expression-7.16.7.tgz#12a6d8522fdd834f194e868af6354e8650242b7a"
  integrity sha512-KyUenhWMC8VrxzkGP0Jizjo4/Zx+1nNZhgocs+gLzyZyB8SHidhoq9KK/8Ato4anhwsivfkBLftky7gvzbZMtQ==
  dependencies:
    "@babel/types" "^7.16.7"`,
			shouldMatch: false,
		},
		// https://github.com/tbenst/purescript-nix-example/blob/558c8d6cb605742218cfa14a3fa93c062324b885/yarn.nix
		{
			name: `invalid_assignable_nix`,
			data: `    {
      name = "_babel_helper_explode_assignable_expression___helper_explode_assignable_expression_7.8.3.tgz";
      path = fetchurl {
        name = "_babel_helper_explode_assignable_expression___helper_explode_assignable_expression_7.8.3.tgz";
        url  = "https://registry.yarnpkg.com/@babel/helper-explode-assignable-expression/-/helper-explode-assignable-expression-7.8.3.tgz";
        sha1 = "a728dc5b4e89e30fc2dfc7d04fa28a930653f982";
      };
    }`,
			shouldMatch: false,
		},
		{
			name: `invalid_assignable`,
			data: `<tr><td colspan="2"><br><h2>Public Member Functions</h2></td></tr>
<tr><td class="memItemLeft" nowrap align="right" valign="top"><a class="anchor" name="b0a0dbf6ca9028bbbb2240cad5882537"></a><!-- doxytag: member="boost::gil::Assignable::constraints" ref="b0a0dbf6ca9028bbbb2240cad5882537" args="()" -->
void&nbsp;</td><td class="memItemRight" valign="bottom"><b>constraints</b> ()</td></tr>
`,
			shouldMatch: false,
		},
		{
			name: `invalid_assignable`,
			data: `File: enumIsAssignableToBuiltInEnum.kt - 6396cf8549625bfce8b8ca2511d7f347
  NL("\n")
  packageHeader`,
			shouldMatch: false,
		},
		{
			name: `invalid_assignable_php`,
			data: `'./include/SugarObjects/forms/PersonFormBase.php' => '2c1846ef127d60a40ecbab2c0b312ff5',
  './include/SugarObjects/implements/assignable/language/en_us.lang.php' => '90f14b03e22e1eed2a1b93e10b975ef5',
  './include/SugarObjects/implements/assignable/vardefs.php' => '358e0c47f753c5577fbdc0de08553c02',
  './include/SugarObjects/implements/security_groups/language/en_us.lang.php' => 'ac1fd4817cb4662e3bdf973836558bdb',`,
			shouldMatch: false,
		},
		// https://github.com/past-due/warzone2100/blob/3e5637a7ed3d67ab92e439b94bf93f89f7bbea51/ChangeLog#L318
		{
			name: `invalid_designable`,
			data: `   * Fix: Prevent map selection button list from going off the form (commit:aea66eb1aa557c73d97b8019e5e66fccbb79f66e, #1347)
   * Fix: Fix odd EMP mortar pathway; Add EMP mortar to designable weapons (commit:bcf93b7fe640c09e8b1239fabfd901fde9760259, #1535)`,
			shouldMatch: false,
		},
		// https://github.com/exis-io/Exis/blob/5383174f7b52112a97aadd09e6b9ea837c2fa07b/CardsAgainstHumanityDemo/swiftCardsAgainst/Pods/Pods.xcodeproj/project.pbxproj
		{
			name: `invalid_designable`,
			data: `		570767CBD99941F484DED46232044DC3 /* DesignableView.swift in Sources */ = {isa = PBXBuildFile; fileRef = 93111B182BD71051B9ED0B14A9EF6EB6 /* DesignableView.swift */; };
		57140D31D50A2FDE1E26729DDE7CB762 /* M13ProgressHUD.h in Headers */ = {isa = PBXBuildFile; fileRef = ECF777CB8B4C090E8D271E62729F7DD3 /* M13ProgressHUD.h */; settings = {ATTRIBUTES = (Public, ); }; };`,
			shouldMatch: false,
		},
		{
			name:        `invalid_designable`,
			data:        `{"nick":"hamster88","message":"this is my gist > https://gist.github.com/thedesignable/a05f628c649a81aae757945c352a8392","date":"2016-06-19T11:05:13.776Z","type":"message"}`,
			shouldMatch: false,
		},
		{
			name: `invalid_designable`,
			data: `返回到故事板文件，选择视图(我将假设从现在起视图被选中)并打开 Identity Inspector。你会注意到一个*可设计的*状态指示器已经出现在自定义类部分。

![Designables status](img/84bc9afc942815899347a31a425af7c6.png)`,
			shouldMatch: false,
		},
		{
			name:        `invalid_designable`,
			data:        `&lt;h3 id=&#34;ibdesignable-x-paintcode:0b699a3cd6d609650a3fca90a5cd32cc&#34;&gt;IBDesignable x PaintCode&lt;/h3&gt;`,
			shouldMatch: false,
		},
		{
			name: `invalid_designable`,
			data: `    </designables>
    <resources>
        <image name="a932cb605eb09bff88b88fdf1c3ef8aa" width="736" height="895"/>
        <image name="plus" catalog="system" width="128" height="113"/>`,
			shouldMatch: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s := Scanner{}

			results, err := s.FromData(context.Background(), false, []byte(test.data))
			if err != nil {
				t.Errorf("Signable.FromData() error = %v", err)
				return
			}

			if test.shouldMatch {
				if len(results) == 0 {
					t.Errorf("%s: did not receive a match for '%v' when one was expected", test.name, test.data)
					return
				}
				expected := test.data
				if test.match != "" {
					expected = test.match
				}
				result := results[0]
				resultData := string(result.Raw)
				if resultData != expected {
					t.Errorf("%s: did not receive expected match.\n\texpected: '%s'\n\t  actual: '%s'", test.name, expected, resultData)
					return
				}
			} else {
				if len(results) > 0 {
					t.Errorf("%s: received a match for '%v' when one wasn't wanted", test.name, test.data)
					return
				}
			}
		})
	}
}
