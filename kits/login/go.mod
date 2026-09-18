// The kit is its own module so that it cannot become a dependency of the
// service, and so that the root module's go.mod carries no replace directive.
//
// The replace points at the SDK in this repository rather than the published
// one, because a kit shipped alongside the server has to demonstrate the API
// the server actually serves. Without it, "go build" resolves sdk/go from the
// module proxy and the kit compiles against whatever was last tagged, which is
// how a reference integration comes to show a call that no longer exists.
module github.com/Socold/n0passtemps/kits/login

go 1.26.0

require github.com/Socold/n0passtemps/sdk/go v1.1.0

replace github.com/Socold/n0passtemps/sdk/go => ../../sdk/go
