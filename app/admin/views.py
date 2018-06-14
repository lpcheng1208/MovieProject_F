import os
from . import admin
from flask import render_template, redirect, url_for, flash, session, request, abort
from app.admin.forms import LoginForm, TagForm, MovieForm, PreviewForm, PwdForm, AuthForm, RoleForm, AdminForm
from app.models import Admin, Tag, Movie, Preview, User, Auth, Role, Comment, Moviecol, Oplog, Adminlog, Userlog
from functools import wraps
from app import db, app
from werkzeug.utils import secure_filename
import uuid
from datetime import datetime


# 上下文应用处理器
@admin.context_processor
def tpl_extra():
    data = dict(online_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    return data


def admin_auth(f):
    """
    权限控制装饰器
    """

    @wraps(f)
    def decorated_function(*args, **kwargs):
        admin = Admin.query.join(
            Role
        ).filter(
            Role.id == Admin.role_id,
            Admin.id == session["admin_id"]
        ).first()
        auths = admin.role.auths
        auths = list(map(lambda v: int(v), auths.split(",")))
        auth_list = Auth.query.all()
        urls = [v.url for v in auth_list for val in auths if val == v.id]
        rule = request.url_rule
        if str(rule) not in urls:
            abort(404)
        return f(*args, **kwargs)

    return decorated_function


def admin_login_req(f):
    """
    登录装饰器
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "admin" not in session:
            return redirect(url_for("admin.login", next=request.url))
        return f(*args, **kwargs)

    return decorated_function


# 修改文件名
def change_filename(filename):
    fileinfo = os.path.splitext(filename)
    filename = datetime.now().strftime("%Y%m%d%H%M%S") + str(uuid.uuid4().hex) + fileinfo[-1]
    return filename


@admin.route("/")
@admin_login_req
def index():
    return render_template("admin/index.html")


# 登录
@admin.route("/login/", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        data = form.data
        admin = Admin.query.filter_by(name=data["account"]).first()
        if not admin.check_pwd(data["pwd"]):
            flash("账号密码错误,请重新输入", "err")
            return redirect(url_for("admin.login"))
        session["admin"] = data["account"]
        session["admin_id"] = admin.id
        adminlog = Adminlog(admin_id=admin.id, ip=request.remote_addr)
        db.session.add(adminlog)
        db.session.commit()
        return redirect(request.args.get("next") or url_for("admin.index"))
    return render_template("admin/login.html", form=form)


@admin.route("/logout/")
@admin_login_req
def logout():
    # 去除session,退出系统
    session.pop("admin", None)
    return redirect(url_for("admin.login"))


@admin.route("/pwd/", methods=["GET", "POST"])
@admin_login_req
def pwd():
    form = PwdForm()
    if form.validate_on_submit():
        data = form.data
        # 通过session查找对应记录
        admin = Admin.query.filter_by(name=session["admin"]).first()
        from werkzeug.security import generate_password_hash
        # 数据库操作保存新密码(hash加密)
        admin.pwd = generate_password_hash(data["new_pwd"])
        db.session.add(admin)
        db.session.commit()
        flash("修改密码成功! 请重新登录!", "ok")
        # 修改成功重定向到退出界面,重新登录
        return redirect(url_for("admin.logout"))
    return render_template("admin/pwd.html", form=form)


@admin.route("/tag/add/", methods=["GET", "POST"])
@admin_login_req
def tag_add():
    form = TagForm()
    if form.validate_on_submit():
        data = form.data
        tag = Tag.query.filter_by(name=data['name']).count()
        if tag == 1:
            flash("标签名已经存在", "err")
            return redirect(url_for("admin.tag_add"))
        tag = Tag(name=data["name"])
        db.session.add(tag)
        db.session.commit()
        flash("添加标签成功", "ok")
        oplog = Oplog(admin_id=session["admin_id"], ip=request.remote_addr, reason="添加标签%s" % data["name"])
        db.session.add(oplog)
        db.session.commit()
        redirect(url_for("admin.tag_add"))

    return render_template("admin/tag_add.html", form=form)


@admin.route("/tag/list/<int:page>/", methods=["GET"])
@admin_login_req
def tag_list(page=None):
    if page is None:
        page = 1
    page_data = Tag.query.order_by(Tag.addtime.desc()).paginate(page=page, per_page=10)
    return render_template("admin/tag_list.html", page_data=page_data)


@admin.route("/tag/del/<int:id>/", methods=["GET"])
@admin_login_req
def tag_del(id=None):
    tag = Tag.query.filter_by(id=id).first_or_404()  # notes: first() or 404()
    db.session.delete(tag)
    db.session.commit()
    flash("删除标签成功", "ok")
    return redirect(url_for("admin.tag_list", page=1))


@admin.route("/tag/edit/<int:id>/", methods=["GET", "POST"])
@admin_login_req
def tag_edit(id=None):
    form = TagForm()
    tag = Tag.query.get_or_404(id)
    if form.validate_on_submit():
        data = form.data
        tag_count = Tag.query.filter_by(name=data['name']).count()
        if tag_count == 1 and data["name"] == tag.name:
            flash("标签名已经存在", "err")
            return redirect(url_for("admin.tag_edit", id=id))
        tag.name = data["name"]
        db.session.add(tag)
        db.session.commit()
        flash("编辑标签成功", "ok")
        return redirect(url_for("admin.tag_edit", id=id))
    return render_template("admin/tag_edit.html", form=form, tag=tag)


@admin.route("/movie/add/", methods=["GET", "POST"])
@admin_login_req
def movie_add():
    form = MovieForm()
    if form.validate_on_submit():
        data = form.data
        file_url = secure_filename(form.url.data.filename)
        file_logo = secure_filename(form.logo.data.filename)
        if not os.path.exists(app.config["UP_DIR"]):
            os.makedirs(app.config["UP_DIR"])
            os.chmod(app.config["UP_DIR"], "rw")
        url = change_filename(file_url)
        logo = change_filename(file_logo)
        form.url.data.save(app.config["UP_DIR"] + url)
        form.logo.data.save(app.config["UP_DIR"] + logo)
        movie = Movie(title=data["title"], url=url, info=data["info"], logo=logo, star=int(data["star"]), playnum=0,
                      commentnum=0, tag_id=int(data["tag_id"]), area=data["area"], release_time=data["release_time"],
                      length=data["length"])
        db.session.add(movie)
        db.session.commit()
        flash("添加电影成功", "ok")
        return redirect(url_for("admin.movie_add"))
    return render_template("admin/movie_add.html", form=form)


@admin.route("/movie/list/<int:page>", methods=["GET"])
@admin_login_req
def movie_list(page=None):
    if page is None:
        page = 1
    page_data = Movie.query.join(Tag).filter(Tag.id == Movie.tag_id).order_by(Movie.addtime.desc()).paginate(page=page,
                                                                                                             per_page=10)
    return render_template("admin/movie_list.html", page_data=page_data)


@admin.route("/movie/del/<int:id>/", methods=["GET"])
@admin_login_req
def movie_del(id=None):
    """
    电影删除
    """
    movie = Movie.query.get_or_404(id)
    db.session.delete(movie)
    db.session.commit()
    flash("电影删除成功", "ok")
    return redirect(url_for('admin.movie_list', page=1))


@admin.route("/movie/edit/<int:id>/", methods=["GET", "POST"])
@admin_login_req
def movie_edit(id=None):
    """
    编辑电影页面
    """
    form = MovieForm()
    # 因为是编辑，所以非空验证空
    form.url.validators = []
    form.logo.validators = []
    movie = Movie.query.get_or_404(int(id))
    if request.method == "GET":
        form.info.data = movie.info
        form.tag_id.data = movie.tag_id
        form.star.data = movie.star
    if form.validate_on_submit():
        data = form.data
        movie_count = Movie.query.filter_by(title=data["title"]).count()
        # 存在一步名字叫这个的电影，有可能是它自己，也有可能是同名。如果是现在的movie不等于要提交的数据中title。那么说明有两个。
        if movie_count == 1 and movie.title == data["title"]:
            flash("片名已经存在！", "err")
            return redirect(url_for('admin.movie_edit', id=id))
        # 创建目录
        if not os.path.exists(app.config["UP_DIR"]):
            os.makedirs(app.config["UP_DIR"])
            os.chmod(app.config["UP_DIR"], "rw")
        # 上传视频
        if form.url.data != "":
            file_url = secure_filename(form.url.data.filename)
            movie.url = change_filename(file_url)
            form.url.data.save(app.config["UP_DIR"] + movie.url)
        # 上传图片
        if form.logo.data != "":
            file_logo = secure_filename(form.logo.data.filename)
            movie.logo = change_filename(file_logo)
            form.logo.data.save(app.config["UP_DIR"] + movie.logo)

        movie.star = int(data["star"])
        movie.tag_id = int(data["tag_id"])
        movie.info = data["info"]
        movie.title = data["title"]
        movie.area = data["area"]
        movie.length = data["length"]
        movie.release_time = data["release_time"]
        db.session.add(movie)
        db.session.commit()
        flash("修改电影成功！", "ok")
        return redirect(url_for('admin.movie_edit', id=id))
    return render_template("admin/movie_edit.html", form=form, movie=movie)


@admin.route("/preview/add/", methods=["GET", "POST"])
@admin_login_req
def preview_add():
    form = PreviewForm()
    if form.validate_on_submit():
        data = form.data
        preview = Preview.query.filter_by(title=data['title']).count()
        if preview == 1:
            flash("预告已经存在", "err")
            return redirect(url_for("admin.preview_add"))
        file_logo = secure_filename(form.logo.data.filename)
        if not os.path.exists(app.config["UP_DIR"]):
            os.makedirs(app.config["UP_DIR"])
            os.chmod(app.config["UP_DIR"], "rw")
        logo = change_filename(file_logo)
        form.logo.data.save(app.config["UP_DIR"] + logo)
        preview = Preview(title=data["title"], logo=logo)
        db.session.add(preview)
        db.session.commit()
        flash("编辑预告成功", "ok")
        return redirect(url_for("admin.preview_add"))
    return render_template("admin/preview_add.html", form=form)


@admin.route("/preview/list/<int:page>/", methods=["GET"])
@admin_login_req
def preview_list(page=None):
    if page is None:
        page = 1
    page_data = Preview.query.order_by(Preview.addtime.desc()).paginate(page=page, per_page=10)
    return render_template("admin/preview_list.html", page_data=page_data)


@admin.route("/preview/del/<int:id>/", methods=["GET"])
@admin_login_req
def preview_del(id=None):
    """
    电影删除
    """
    preview = Preview.query.get_or_404(id)
    db.session.delete(preview)
    db.session.commit()
    flash("电影删除成功", "ok")
    return redirect(url_for('admin.preview_list', page=1))


@admin.route("/preview/edit/<int:id>/", methods=["GET", "POST"])
@admin_login_req
def preview_edit(id):
    form = PreviewForm()
    preview = Preview.query.get_or_404(int(id))
    if request.method == "GET":
        form.title.data = preview.title
    if form.validate_on_submit():
        data = form.data
        if form.logo.data != "":
            file_logo = secure_filename(form.logo.data.filename)
            preview.logo = change_filename(file_logo)
            form.logo.data.save(app.config["UP_DIR"] + preview.logo)
        preview.title = data["title"]
        db.session.add(preview)
        db.session.commit()
        flash("编辑预告成功", "ok")
        return redirect(url_for("admin.preview_edit", id=id))
    return render_template("admin/preview_edit.html", form=form, preview=preview)


@admin.route("/user/list/<int:page>/", methods=["GET"])
@admin_login_req
def user_list(page):
    if page is None:
        page = 1
    page_data = User.query.order_by(User.addtime.desc()).paginate(page=page, per_page=10)
    return render_template("admin/user_list.html", page_data=page_data)


@admin.route("/user/view/<int:id>/", methods=["GET"])
@admin_login_req
def user_view(id=None):
    user = User.query.get_or_404(int(id))

    return render_template("admin/user_view.html", user=user)


@admin.route("/user/del/<int:id>/", methods=["GET"])
@admin_login_req
def user_del(id=None):
    """
    电影删除
    """
    user = User.query.get_or_404(id)
    db.session.delete(user)
    db.session.commit()
    flash("用户删除成功", "ok")
    return redirect(url_for('admin.user_list', page=1))


@admin.route("/comment/list/<int:page>/", methods=["GET"])
@admin_login_req
def comment_list(page=None):
    if page is None:
        page = 1
    page_data = Comment.query.join(Movie).join(User).filter(Movie.id == Comment.movie_id,
                                                            User.id == Comment.user_id).order_by(
        Comment.addtime.desc()).paginate(page=page, per_page=10)
    return render_template("admin/comment_list.html", page_data=page_data)


@admin.route("/comment/del/<int:id>/", methods=["GET"])
@admin_login_req
def comment_del(id=None):
    """
    电影删除
    """
    comment = Comment.query.get_or_404(id)
    db.session.delete(comment)
    db.session.commit()
    flash("评论删除成功", "ok")
    return redirect(url_for('admin.comment_list', page=1))


@admin.route("/moviecol/list/<int:page>/", methods=["GET"])
@admin_login_req
def moviecol_list(page):
    if page is None:
        page = 1
    page_data = Moviecol.query.join(Movie).join(User).filter(Moviecol.movie_id == Movie.id,
                                                             Moviecol.user_id == User.id).order_by(
        Moviecol.addtime.desc()).paginate(page=page, per_page=10)
    return render_template("admin/moviecol_list.html", page_data=page_data)


@admin.route("/moviecol/del/<int:id>/")
@admin_login_req
def moviecol_del(id=None):
    moviecol = Moviecol.query.get_or_404(int(id))
    db.session.delete(moviecol)
    db.session.commit()
    flash("删除收藏成功", "ok")
    return redirect(url_for("admin.moviecol_list", page=1))


@admin.route("/oplog/list/<int:page>/", methods=["GET"])
@admin_login_req
def oplog_list(page=None):
    if page is None:
        page = 1
    page_data = Oplog.query.join(Admin).filter(Oplog.admin_id == Admin.id).order_by(Oplog.addtime.desc()).paginate(
        page=page, per_page=10)
    return render_template("admin/oplog_list.html", page_data=page_data)


@admin.route("/adminloginlog/list/<int:page>/", methods=["GET"])
@admin_login_req
def adminloginlog_list(page=None):
    if page is None:
        page = 1
    page_data = Adminlog.query.join(Admin).filter(Adminlog.admin_id == Admin.id).order_by(
        Adminlog.addtime.desc()).paginate(page=page, per_page=10)
    return render_template("admin/adminloginlog_list.html", page_data=page_data)


@admin.route("/userloginlog/list/<int:page>/", methods=["GET"])
@admin_login_req
def userloginlog_list(page=None):
    if page is None:
        page = 1
    page_data = Userlog.query.join(
        User
    ).filter(
        User.id == Userlog.user_id
    ).order_by(
        Userlog.addtime.desc()
    ).paginate(page=page, per_page=10)
    return render_template("admin/userloginlog_list.html", page_data=page_data)


@admin.route("/role/add/", methods=["GET", "POST"])
@admin_login_req
def role_add():
    form = RoleForm()
    if form.validate_on_submit():
        data = form.data
        role = Role.query.filter_by(name=data['name']).count()
        if role == 1:
            flash("角色已经存在", "err")
            return redirect(url_for("admin.role_add"))
        role = Role(name=data["name"], auths=",".join(map(lambda v: str(v), data["auths"])))
        db.session.add(role)
        db.session.commit()
        flash("添加角色成功! ", "ok")
    return render_template("admin/role_add.html", form=form)


@admin.route("/role/list/<int:page>/", methods=["GET"])
@admin_login_req
def role_list(page=None):
    if page is None:
        page = 1
    page_data = Role.query.order_by(
        Role.addtime.desc()
    ).paginate(page=page, per_page=10)
    return render_template("admin/role_list.html", page_data=page_data)


@admin.route("/role/del/<int:id>/", methods=["GET", "POST"])
@admin_login_req
def role_del(id=None):
    role = Role.query.get_or_404(int(id))
    db.session.delete(role)
    db.session.commit()
    flash("删除角色成功!", "ok")
    return redirect(url_for("admin.role_list", page=1))


@admin.route("/role/edit/<int:id>/", methods=["GET", "POST"])
@admin_login_req
def role_edit(id=None):
    form = RoleForm()
    role = Role.query.get_or_404(id)
    if request.method == "GET" and role.id != 1:
        auths = role.auths
        form.auths.data = list(map(lambda v: int(v), auths.split(",")))
    if form.validate_on_submit():
        data = form.data
        # role_count = Role.query.filter_by(name=data['name']).count()
        # if role_count == 1 and data["name"] == role.name:
        #     flash("角色已经存在", "err")
        #     return redirect(url_for("admin.role_edit", id=id))
        role.name = data["name"]
        role.auths = ",".join(map(lambda v: str(v), data["auths"]))
        db.session.add(role)
        db.session.commit()
        flash("编辑标签成功", "ok")
        return redirect(url_for("admin.role_edit", id=id))
    return render_template("admin/role_edit.html", form=form, role=role)


@admin.route("/auth/add/", methods=["GET", "POST"])
@admin_login_req
def auth_add():
    form = AuthForm()
    if form.validate_on_submit():
        data = form.data
        auths = Auth(name=data["name"], url=data["url"])
        db.session.add(auths)
        db.session.commit()
        flash("添加权限成功!", "ok")
    return render_template("admin/auth_add.html", form=form)


@admin.route("/auth/list/<int:page>/", methods=["GET"])
@admin_login_req
def auth_list(page=None):
    if page is None:
        page = 1
    page_data = Auth.query.order_by(Auth.addtime.desc()).paginate(page=page, per_page=10)
    return render_template("admin/auth_list.html", page_data=page_data)


@admin.route("/auth/del/<int:id>/", methods=["GET", "POST"])
@admin_login_req
def auth_del(id=None):
    auth = Auth.query.get_or_404(int(id))
    db.session.delete(auth)
    db.session.commit()
    flash("删除权限成功!", "ok")
    return redirect(url_for("admin.auth_list", page=1))


@admin.route("/auth/edit/<int:id>/", methods=["GET", "POST"])
@admin_login_req
def auth_edit(id=None):
    form = AuthForm()
    auth = Auth.query.get_or_404(int(id))
    if form.validate_on_submit():
        data = form.data
        # auth_count = Auth.query.filter_by(name=data['name']).count()
        # if auth_count == 1 and data["name"] == auth.name:
        #     flash("权限已经存在", "err")
        #     return redirect(url_for("admin.auth_edit", id=id))
        auth.name = data["name"]
        auth.url = data["url"]
        db.session.add(auth)
        db.session.commit()
        flash("编辑权限成功", "ok")
        return redirect(url_for("admin.auth_edit", id=id))
    return render_template("admin/auth_edit.html", form=form, auth=auth)


#  添加管理员
@admin.route("/admin/add/", methods=["GET", "POST"])
@admin_login_req
def admin_add():
    form = AdminForm()
    from werkzeug.security import generate_password_hash
    if form.validate_on_submit():
        data = form.data
        admin = Admin.query.filter_by(name=data["name"]).first()
        if admin:
            flash("管理员已经存在", "err")
            return redirect(url_for("admin.admin_add"))
        admin = Admin(
            name=data["name"],
            pwd=generate_password_hash(data["pwd"]),
            is_super=data["is_super"],
            role_id=data["role_id"]
        )
        db.session.add(admin)
        db.session.commit()
        flash("管理员添加成功", "ok")
        return redirect(url_for("admin.admin_add"))
    return render_template("admin/admin_add.html", form=form)


#  管理员列表
@admin.route("/admin/list/<int:page>/", methods=["GET"])
@admin_login_req
def admin_list(page=None):
    if page is None:
        page = 1
    page_data = Admin.query.join(
        Role
    ).filter(
        Role.id == Admin.role_id
    ).order_by(
        Admin.addtime.desc()
    ).paginate(page=page, per_page=10)
    return render_template("admin/admin_list.html", page_data=page_data)


@admin.route("/admin/del/<int:id>/", methods=["POST", "GET"])
@admin_login_req
def admin_del(id=None):
    admin = Admin.query.get_or_404(int(id))
    db.session.delete(admin)
    db.session.commit()
    flash("删除管理员成功!", "ok")
    return redirect(url_for("admin.admin_list", page=1))


@admin.route("/admin/edit/<int:id>/", methods=["POST", "GET"])
@admin_login_req
def admin_edit(id=None):
    from werkzeug.security import generate_password_hash
    form = AdminForm()
    admin = Admin.query.get_or_404(int(id))
    if request.method == "GET":
        form.is_super.data = admin.is_super
        form.role_id.data = admin.role_id
    if form.validate_on_submit():
        data = form.data
        # auth_count = Auth.query.filter_by(name=data['name']).count()
        # if auth_count == 1 and data["name"] == auth.name:
        #     flash("权限已经存在", "err")
        #     return redirect(url_for("admin.auth_edit", id=id))
        admin.name = data["name"]
        admin.is_super = data["is_super"]
        admin.role_id = data["role_id"]
        admin.pwd = generate_password_hash(data["name"])
        db.session.add(admin)
        db.session.commit()
        flash("编辑管理员成功", "ok")
        return redirect(url_for("admin.admin_edit", id=id))
    return render_template("admin/admin_edit.html", form=form, admin=admin)