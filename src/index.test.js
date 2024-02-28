const resolve = require("./index");

test('Test resolve', async () => {
    expect(await resolve("li0ard")).toBe(`05fc331b505085fecc2188707c1da8002ee3edc6eb5591e36ded40a4669a94ab11`);
})